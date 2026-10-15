use std::io::{self, Read, Write};

use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

use crate::crypt::errors::CryptError;

// Lift an I/O error into a [`CryptError`].
#[inline]
fn io_err(e: io::Error) -> CryptError {
    CryptError::Error("I/O error".to_string(), e.to_string())
}

// Read from reader until buf is full or EOF is reached.
// Returns the number of bytes read; `< buf.len()` means EOF was hit.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

// Derive a per-chunk nonce from a 12-byte `base_nonce` and a 64-bit
// chunk counter, ensuring every chunk is encrypted under a unique nonce.
//
// Layout of the resulting nonce (12 bytes):
//   bytes 0–3  : base_nonce[0..4]  (unchanged)
//   bytes 4–11 : base_nonce[4..12] XOR counter.to_le_bytes()
fn chunk_nonce(base_nonce: &[u8; 12], counter: u64) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let counter_bytes = counter.to_le_bytes(); // 8 bytes
    for i in 0..8 {
        nonce[4 + i] ^= counter_bytes[i];
    }
    nonce
}

// Encrypt all bytes from `input` into `writer` in `chunk_size`-byte blocks.
//
// On-disk chunk layout (repeated until EOF):
//   [ chunk_len  (4 B, LE u32) ]  ← length of the following ciphertext
//   [ ciphertext (chunk_len B) ]  ← raw data + 16-byte GCM tag
// A zero `chunk_len` marks the end of the stream.
fn stream_encrypt(
    cipher: &Aes256Gcm,
    base_nonce: &[u8; 12],
    input: &mut impl Read,
    writer: &mut impl Write,
    chunk_size: usize,
) -> Result<(), CryptError> {
    let mut buf = vec![0u8; chunk_size];
    let mut counter: u64 = 0;

    loop {
        let n = read_full(input, &mut buf).map_err(io_err)?;

        let nonce = Nonce::from(chunk_nonce(base_nonce, counter));
        let ct = cipher.encrypt(&nonce, &buf[..n]).map_err(|e| {
            CryptError::AesGcmError(
                format!("Encryption error on chunk {counter}"),
                e.to_string(),
            )
        })?;

        // Write length-prefixed ciphertext chunk.
        writer
            .write_all(&(ct.len() as u32).to_le_bytes())
            .map_err(io_err)?;
        writer.write_all(&ct).map_err(io_err)?;

        counter += 1;

        if n < chunk_size {
            break; // EOF reached
        }
    }

    // End-of-stream sentinel: a zero-length chunk.
    writer.write_all(&0u32.to_le_bytes()).map_err(io_err)?;
    writer.flush().map_err(io_err)
}

// Decrypt all length-prefixed ciphertext chunks from `reader` into `writer`.
//
// The first bytes of the decrypted stream are the filename header:
// `[filename_len (4 B LE)] ++ [filename bytes]`. These are stripped and
// returned; all subsequent bytes are written to `writer`.
fn stream_decrypt(
    cipher: &Aes256Gcm,
    base_nonce: &[u8; 12],
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<String, CryptError> {
    let mut counter: u64 = 0;

    // Bytes accumulated until the filename header is fully parsed.
    // Never exceeds one chunk worth of data.
    let mut hdr_buf: Vec<u8> = Vec::new();
    let mut filename: Option<String> = None;

    loop {
        // Read the 4-byte chunk length prefix.
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).map_err(io_err)?;
        let ct_len = u32::from_le_bytes(len_buf) as usize;

        if ct_len == 0 {
            break; // End-of-stream sentinel
        }

        // Read and decrypt the ciphertext chunk.
        let mut ct = vec![0u8; ct_len];
        reader.read_exact(&mut ct).map_err(io_err)?;

        let nonce = Nonce::from(chunk_nonce(base_nonce, counter));
        let decrypted = cipher.decrypt(&nonce, ct.as_slice()).map_err(|e| {
            CryptError::AesGcmError(
                format!(
                    "Failed to decrypt chunk {counter} \
                     (corrupted or tampered data)"
                ),
                e.to_string(),
            )
        })?;

        counter += 1;

        // Extract filename header (runs only for the first chunk(s))
        if filename.is_none() {
            hdr_buf.extend_from_slice(&decrypted);

            if hdr_buf.len() >= 4 {
                let name_len = u32::from_le_bytes(hdr_buf[0..4].try_into().unwrap()) as usize;
                let hdr_end = 4 + name_len;

                if hdr_buf.len() >= hdr_end {
                    filename = Some(String::from_utf8(hdr_buf[4..hdr_end].to_vec()).map_err(
                        |e| {
                            CryptError::Error(
                                "Filename contains invalid UTF-8".to_string(),
                                e.to_string(),
                            )
                        },
                    )?);
                    // Write any file-data bytes that followed the header.
                    if hdr_buf.len() > hdr_end {
                        writer.write_all(&hdr_buf[hdr_end..]).map_err(io_err)?;
                    }
                    hdr_buf.clear();
                }
            }
        } else {
            writer.write_all(&decrypted).map_err(io_err)?;
        }
    }

    writer.flush().map_err(io_err)?;

    filename.ok_or_else(|| {
        CryptError::Error(
            "Decrypted stream too short to contain a valid filename header".to_string(),
            "".to_string(),
        )
    })
}

// ─── keystore-based encrypt / decrypt ────────────────────────────────────────

// Encrypt `reader` into `writer` protected by a keystore master key.
//
// On-disk layout
// ┌────────────────────────────────────────────────────────────┐
// │  DEK nonce        (12 B)                                   │
// │  Wrapped-DEK len  ( 4 B, little-endian u32)                │
// │  Wrapped DEK      (variable)                               │
// │  Base nonce       (12 B)  ← per-file stream base nonce     │
// │  Chunk 0 len      ( 4 B, LE u32)                           │
// │  Chunk 0 data     (chunk_len B)  ← CHUNK_SIZE + 16 B max   │
// │  …                                                         │
// │  EOS sentinel     ( 4 B, all zero)                         │
// └────────────────────────────────────────────────────────────┘
// The data stream is `[filename_len (4 B LE)] ++ [filename] ++ [file bytes]`.
pub fn encrypt_file_wks(
    master_key: &[u8; 32],
    filename: &str,
    reader: &mut impl Read,
    writer: &mut impl Write,
    chunk_size: usize,
) -> Result<(), CryptError> {
    // KEK cipher
    let kek = Key::<Aes256Gcm>::try_from(master_key.as_slice()).map_err(|e| {
        CryptError::AesGcmError(
            "Error Generating Key from Master Key".to_string(),
            e.to_string(),
        )
    })?;
    let master_cipher = Aes256Gcm::new(&kek);

    // Per-file DEK
    let mut file_dek = [0u8; 32];
    rand::fill(&mut file_dek);

    // Wrap DEK with master key (KEK)
    let mut dek_nonce_bytes = [0u8; 12];
    rand::fill(&mut dek_nonce_bytes);
    let wrapped_dek = master_cipher
        .encrypt(&Nonce::from(dek_nonce_bytes), file_dek.as_ref())
        .map_err(|e| {
            CryptError::AesGcmError(
                "Error occurred while encrypting file DEK Key".to_string(),
                e.to_string(),
            )
        })?;

    // Base nonce for chunk-derived nonces
    let mut base_nonce = [0u8; 12];
    rand::fill(&mut base_nonce);

    // Write header
    writer.write_all(&dek_nonce_bytes).map_err(io_err)?;
    writer
        .write_all(&(wrapped_dek.len() as u32).to_le_bytes())
        .map_err(io_err)?;
    writer.write_all(&wrapped_dek).map_err(io_err)?;
    writer.write_all(&base_nonce).map_err(io_err)?;

    // Build file DEK cipher
    let file_key = Key::<Aes256Gcm>::try_from(file_dek.as_slice()).map_err(|e| {
        CryptError::AesGcmError("Error generating Key from DEK".to_string(), e.to_string())
    })?;
    let file_cipher = Aes256Gcm::new(&file_key);

    // Prepend filename header then chain with file data
    let mut hdr = Vec::with_capacity(4 + filename.len());
    hdr.extend_from_slice(&(filename.len() as u32).to_le_bytes());
    hdr.extend_from_slice(filename.as_bytes());
    let mut input_data = io::Cursor::new(hdr).chain(reader);

    stream_encrypt(
        &file_cipher,
        &base_nonce,
        &mut input_data,
        writer,
        chunk_size,
    )
}

// Decrypt `reader` into `writer` using a keystore master key.
// Returns the original filename embedded in the ciphertext stream.
pub fn decrypt_file_wks(
    master_key: &[u8; 32],
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<String, CryptError> {
    // ── KEK cipher ───────────────────────────────────────────────────────────
    let kek = Key::<Aes256Gcm>::try_from(master_key.as_slice()).map_err(|e| {
        CryptError::AesGcmError(
            "Error Generating Key from Master Key".to_string(),
            e.to_string(),
        )
    })?;
    let master_cipher = Aes256Gcm::new(&kek);

    // ── Read and parse header ─────────────────────────────────────────────────
    let mut dek_nonce_bytes = [0u8; 12];
    reader.read_exact(&mut dek_nonce_bytes).map_err(io_err)?;

    let mut dek_len_buf = [0u8; 4];
    reader.read_exact(&mut dek_len_buf).map_err(io_err)?;
    let dek_len = u32::from_le_bytes(dek_len_buf) as usize;

    let mut wrapped_dek = vec![0u8; dek_len];
    reader.read_exact(&mut wrapped_dek).map_err(io_err)?;

    let mut base_nonce = [0u8; 12];
    reader.read_exact(&mut base_nonce).map_err(io_err)?;

    // ── Unwrap DEK ────────────────────────────────────────────────────────────
    let file_dek_vec = master_cipher
        .decrypt(&Nonce::from(dek_nonce_bytes), wrapped_dek.as_ref())
        .map_err(|e| {
            CryptError::AesGcmError(
                "Error occurred while decrypting DEK Key of file using master password".to_string(),
                e.to_string(),
            )
        })?;
    let file_dek: [u8; 32] = file_dek_vec.try_into().map_err(|_| {
        CryptError::Error(
            "Decrypted DEK must be exactly 32 bytes".to_string(),
            "".to_string(),
        )
    })?;
    let file_key = Key::<Aes256Gcm>::try_from(file_dek.as_slice()).map_err(|e| {
        CryptError::AesGcmError("Error generating Key from DEK".to_string(), e.to_string())
    })?;
    let file_cipher = Aes256Gcm::new(&file_key);

    stream_decrypt(&file_cipher, &base_nonce, reader, writer)
}

// password-based encrypt / decrypt

// Derive a KEK from `password` and a base64-encoded `salt_str` via Argon2.
fn derive_kek_from_pwd(password: &str, salt_str: &str) -> Result<[u8; 32], CryptError> {
    let salt = SaltString::from_b64(salt_str).map_err(|e| {
        CryptError::Argon2Error("Unable to generate salt".to_string(), e.to_string())
    })?;
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| {
            CryptError::Argon2Error("Unable to hash password".to_string(), e.to_string())
        })?;

    let hash_bytes = password_hash.hash.ok_or(CryptError::Argon2Error(
        "Failed to extract raw hash bytes from password hash".to_string(),
        "".to_string(),
    ))?;

    let mut key = [0u8; 32];
    let n = hash_bytes.as_bytes().len().min(32);
    key[..n].copy_from_slice(&hash_bytes.as_bytes()[..n]);
    Ok(key)
}

// Encrypt `reader` into `writer` protected by a password.
//
// On-disk layout
// ┌────────────────────────────────────────────────────────────┐
// │  Salt             (16 B)                                   │
// │  DEK nonce        (12 B)                                   │
// │  Wrapped-DEK len  ( 4 B, little-endian u32)                │
// │  Wrapped DEK      (variable)                               │
// │  Base nonce       (12 B)                                   │
// │  Chunk 0 len      ( 4 B, LE u32)                           │
// │  Chunk 0 data     (chunk_len B)                            │
// │  …                                                         │
// │  EOS sentinel     ( 4 B, all zero)                         │
// └────────────────────────────────────────────────────────────┘
pub fn encrypt_file_with_pwd(
    password: &str,
    filename: &str,
    reader: &mut impl Read,
    writer: &mut impl Write,
    chunk_size: usize,
) -> Result<(), CryptError> {
    // Derive KEK from password + fresh salt
    let mut salt_bytes = [0u8; 16];
    rand::fill(&mut salt_bytes);
    let salt_string = SaltString::encode_b64(&salt_bytes).map_err(|e| {
        CryptError::Argon2Error("Unable to generate Salt String".to_string(), e.to_string())
    })?;
    let kek_bytes = derive_kek_from_pwd(password, salt_string.as_str())?;
    let kek = Key::<Aes256Gcm>::try_from(kek_bytes.as_slice()).map_err(|e| {
        CryptError::AesGcmError(
            "Error ocurred generating Key from KEK Bytes".to_string(),
            e.to_string(),
        )
    })?;
    let master_cipher = Aes256Gcm::new(&kek);

    // Per-file DEK
    let mut file_dek = [0u8; 32];
    rand::fill(&mut file_dek);

    // Wrap DEK with KEK
    let mut dek_nonce_bytes = [0u8; 12];
    rand::fill(&mut dek_nonce_bytes);
    let wrapped_dek = master_cipher
        .encrypt(&Nonce::from(dek_nonce_bytes), file_dek.as_ref())
        .map_err(|e| {
            CryptError::AesGcmError(
                "Error occurred encrypting DEK Key using password-derived KEK".to_string(),
                e.to_string(),
            )
        })?;

    // Base nonce for chunk-derived nonces
    let mut base_nonce = [0u8; 12];
    rand::fill(&mut base_nonce);

    // Write header
    writer.write_all(&salt_bytes).map_err(io_err)?; // 16 B raw salt
    writer.write_all(&dek_nonce_bytes).map_err(io_err)?;
    writer
        .write_all(&(wrapped_dek.len() as u32).to_le_bytes())
        .map_err(io_err)?;
    writer.write_all(&wrapped_dek).map_err(io_err)?;
    writer.write_all(&base_nonce).map_err(io_err)?;

    // Build file DEK cipher
    let file_key = Key::<Aes256Gcm>::try_from(file_dek.as_slice()).map_err(|e| {
        CryptError::AesGcmError(
            "Error ocurred generating Key from DEK Bytes".to_string(),
            e.to_string(),
        )
    })?;
    let file_cipher = Aes256Gcm::new(&file_key);

    // Prepend filename header then chain with file data
    let mut hdr = Vec::with_capacity(4 + filename.len());
    hdr.extend_from_slice(&(filename.len() as u32).to_le_bytes());
    hdr.extend_from_slice(filename.as_bytes());
    let mut input_data = io::Cursor::new(hdr).chain(reader);

    stream_encrypt(
        &file_cipher,
        &base_nonce,
        &mut input_data,
        writer,
        chunk_size,
    )
}

// Decrypt `reader` into `writer` using a password.
// Returns the original filename embedded in the ciphertext stream.
pub fn decrypt_file_with_pwd(
    password: &str,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<String, CryptError> {
    // Read salt and re-derive KEK
    let mut salt_bytes = [0u8; 16];
    reader.read_exact(&mut salt_bytes).map_err(io_err)?;
    let salt_string = SaltString::encode_b64(&salt_bytes).map_err(|e| {
        CryptError::Argon2Error(
            "Error occurred while encoding salt bytes to salt string".to_string(),
            e.to_string(),
        )
    })?;
    let kek_bytes = derive_kek_from_pwd(password, salt_string.as_str())?;
    let kek = Key::<Aes256Gcm>::try_from(kek_bytes.as_slice()).map_err(|e| {
        CryptError::AesGcmError(
            "Error ocurred generating Key from KEK Bytes".to_string(),
            e.to_string(),
        )
    })?;
    let master_cipher = Aes256Gcm::new(&kek);

    // Read rest of header
    let mut dek_nonce_bytes = [0u8; 12];
    reader.read_exact(&mut dek_nonce_bytes).map_err(io_err)?;

    let mut dek_len_buf = [0u8; 4];
    reader.read_exact(&mut dek_len_buf).map_err(io_err)?;
    let dek_len = u32::from_le_bytes(dek_len_buf) as usize;

    let mut wrapped_dek = vec![0u8; dek_len];
    reader.read_exact(&mut wrapped_dek).map_err(io_err)?;

    let mut base_nonce = [0u8; 12];
    reader.read_exact(&mut base_nonce).map_err(io_err)?;

    // Unwrap DEK
    let file_dek_vec = master_cipher
        .decrypt(&Nonce::from(dek_nonce_bytes), wrapped_dek.as_ref())
        .map_err(|e| {
            CryptError::AesGcmError(
                "Failed to unwrap file DEK (Incorrect password or corrupted payload)".to_string(),
                e.to_string(),
            )
        })?;
    let file_dek: [u8; 32] = file_dek_vec.try_into().map_err(|_| {
        CryptError::Error(
            "Decrypted DEK must be exactly 32 bytes".to_string(),
            "".to_string(),
        )
    })?;
    let file_key = Key::<Aes256Gcm>::try_from(file_dek.as_slice()).map_err(|e| {
        CryptError::AesGcmError("Error generating Key from DEK".to_string(), e.to_string())
    })?;
    let file_cipher = Aes256Gcm::new(&file_key);

    stream_decrypt(&file_cipher, &base_nonce, reader, writer)
}
