use std::io::{self, Read, Write};

use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

use crate::crypt::errors::CryptError;

// Header Constants & Types
pub const MAGIC_BYTES: &[u8; 4] = b"TFMR";
pub const CURRENT_FORMAT_VERSION: u8 = 1;

const TOOL_VERSION_MAJOR: u8 = match u8::from_str_radix(env!("CARGO_PKG_VERSION_MAJOR"), 10) {
    Ok(v) => v,
    Err(_) => 0,
};
const TOOL_VERSION_MINOR: u8 = match u8::from_str_radix(env!("CARGO_PKG_VERSION_MINOR"), 10) {
    Ok(v) => v,
    Err(_) => 0,
};
const TOOL_VERSION_PATCH: u8 = match u8::from_str_radix(env!("CARGO_PKG_VERSION_PATCH"), 10) {
    Ok(v) => v,
    Err(_) => 0,
};
pub const CURRENT_TOOL_VERSION: [u8; 3] = [
    TOOL_VERSION_MAJOR,
    TOOL_VERSION_MINOR,
    TOOL_VERSION_PATCH,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptionMode {
    Keystore = 1,
    Password = 2,
}

impl EncryptionMode {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(EncryptionMode::Keystore),
            2 => Some(EncryptionMode::Password),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherSuite {
    Aes256Gcm = 1,
}

impl CipherSuite {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(CipherSuite::Aes256Gcm),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub format_version: u8,
    pub mode: EncryptionMode,
    pub cipher_suite: CipherSuite,
    pub tool_version: [u8; 3],
}

// Write the common header bytes into the writer.
//
// Header layout (10 B total):
//   Magic Bytes    (4 B) : b"TFMR"
//   Format Version (1 B) : 0x01
//   Mode           (1 B) : 0x01 (Keystore) or 0x02 (Password)
//   Cipher Suite   (1 B) : 0x01 (AES-256-GCM)
//   Tool Version   (3 B) : [major, minor, patch]
pub fn write_header(
    writer: &mut impl Write,
    mode: EncryptionMode,
    cipher_suite: CipherSuite,
) -> Result<(), CryptError> {
    writer.write_all(MAGIC_BYTES).map_err(io_err)?;
    writer.write_all(&[CURRENT_FORMAT_VERSION]).map_err(io_err)?;
    writer.write_all(&[mode as u8]).map_err(io_err)?;
    writer.write_all(&[cipher_suite as u8]).map_err(io_err)?;
    writer.write_all(&CURRENT_TOOL_VERSION).map_err(io_err)?;
    Ok(())
}

// Read and validate the common header from the reader.
pub fn read_file_header(reader: &mut impl Read) -> Result<FileHeader, CryptError> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic).map_err(io_err)?;
    if &magic != MAGIC_BYTES {
        return Err(CryptError::InvalidHeader(format!(
            "Invalid magic bytes: expected {:?}, found {:?}",
            MAGIC_BYTES, magic
        )));
    }

    let mut ver_buf = [0u8; 1];
    reader.read_exact(&mut ver_buf).map_err(io_err)?;
    let format_version = ver_buf[0];
    if format_version != CURRENT_FORMAT_VERSION {
        return Err(CryptError::InvalidHeader(format!(
            "Unsupported format version {format_version} (supported version: {CURRENT_FORMAT_VERSION})"
        )));
    }

    let mut mode_buf = [0u8; 1];
    reader.read_exact(&mut mode_buf).map_err(io_err)?;
    let mode = EncryptionMode::from_u8(mode_buf[0]).ok_or_else(|| {
        CryptError::InvalidHeader(format!("Unknown encryption mode: {}", mode_buf[0]))
    })?;

    let mut cipher_buf = [0u8; 1];
    reader.read_exact(&mut cipher_buf).map_err(io_err)?;
    let cipher_suite = CipherSuite::from_u8(cipher_buf[0]).ok_or_else(|| {
        CryptError::InvalidHeader(format!("Unknown cipher suite: {}", cipher_buf[0]))
    })?;

    let mut tool_version = [0u8; 3];
    reader.read_exact(&mut tool_version).map_err(io_err)?;

    Ok(FileHeader {
        format_version,
        mode,
        cipher_suite,
        tool_version,
    })
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
// │  Magic bytes      ( 4 B)  b"TFMR"                          │
// │  Format version   ( 1 B)  0x01                             │
// │  Mode             ( 1 B)  0x01 (Keystore)                  │
// │  Cipher suite     ( 1 B)  0x01 (AES-256-GCM)               │
// │  Tool version     ( 3 B)  [major, minor, patch]            │
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
    write_header(writer, EncryptionMode::Keystore, CipherSuite::Aes256Gcm)?;
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
    // ── Header validation ────────────────────────────────────────────────────
    let header = read_file_header(reader)?;
    if header.mode != EncryptionMode::Keystore {
        return Err(CryptError::InvalidHeader(format!(
            "Expected keystore encryption mode, but found {:?}",
            header.mode
        )));
    }
    if header.cipher_suite != CipherSuite::Aes256Gcm {
        return Err(CryptError::InvalidHeader(format!(
            "Unsupported cipher suite: {:?}",
            header.cipher_suite
        )));
    }

    // ── KEK cipher ───────────────────────────────────────────────────────────
    let kek = Key::<Aes256Gcm>::try_from(master_key.as_slice()).map_err(|e| {
        CryptError::AesGcmError(
            "Error Generating Key from Master Key".to_string(),
            e.to_string(),
        )
    })?;
    let master_cipher = Aes256Gcm::new(&kek);

    // ── Read and parse payload header ─────────────────────────────────────────
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

// ─── password-based encrypt / decrypt ────────────────────────────────────────

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
// │  Magic bytes      ( 4 B)  b"TFMR"                          │
// │  Format version   ( 1 B)  0x01                             │
// │  Mode             ( 1 B)  0x02 (Password)                  │
// │  Cipher suite     ( 1 B)  0x01 (AES-256-GCM)               │
// │  Tool version     ( 3 B)  [major, minor, patch]            │
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
    write_header(writer, EncryptionMode::Password, CipherSuite::Aes256Gcm)?;
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
    // ── Header validation ────────────────────────────────────────────────────
    let header = read_file_header(reader)?;
    if header.mode != EncryptionMode::Password {
        return Err(CryptError::InvalidHeader(format!(
            "Expected password encryption mode, but found {:?}",
            header.mode
        )));
    }
    if header.cipher_suite != CipherSuite::Aes256Gcm {
        return Err(CryptError::InvalidHeader(format!(
            "Unsupported cipher suite: {:?}",
            header.cipher_suite
        )));
    }

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

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_password_encrypt_decrypt_roundtrip() {
        let password = "SuperSecretPassword123!";
        let original_filename = "document.txt";
        let original_data = b"Hello world! This is confidential data being encrypted with headers.";

        let mut encrypted = Vec::new();
        encrypt_file_with_pwd(
            password,
            original_filename,
            &mut Cursor::new(original_data),
            &mut encrypted,
            16, // small chunk size to test multi-chunk streaming
        )
        .expect("encryption failed");

        // Verify header inspectability
        let mut enc_cursor = Cursor::new(&encrypted);
        let header = read_file_header(&mut enc_cursor).expect("failed to read header");
        assert_eq!(header.format_version, CURRENT_FORMAT_VERSION);
        assert_eq!(header.mode, EncryptionMode::Password);
        assert_eq!(header.cipher_suite, CipherSuite::Aes256Gcm);
        assert_eq!(header.tool_version, CURRENT_TOOL_VERSION);

        // Decrypt
        let mut decrypted = Vec::new();
        let mut enc_reader = Cursor::new(&encrypted);
        let recovered_filename =
            decrypt_file_with_pwd(password, &mut enc_reader, &mut decrypted)
                .expect("decryption failed");

        assert_eq!(recovered_filename, original_filename);
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_keystore_encrypt_decrypt_roundtrip() {
        let master_key = [42u8; 32];
        let original_filename = "archive.tar";
        let original_data = b"Some binary contents to encrypt with keystore key.";

        let mut encrypted = Vec::new();
        encrypt_file_wks(
            &master_key,
            original_filename,
            &mut Cursor::new(original_data),
            &mut encrypted,
            32,
        )
        .expect("keystore encryption failed");

        // Verify header
        let mut enc_cursor = Cursor::new(&encrypted);
        let header = read_file_header(&mut enc_cursor).expect("failed to read header");
        assert_eq!(header.format_version, CURRENT_FORMAT_VERSION);
        assert_eq!(header.mode, EncryptionMode::Keystore);
        assert_eq!(header.cipher_suite, CipherSuite::Aes256Gcm);

        // Decrypt
        let mut decrypted = Vec::new();
        let mut enc_reader = Cursor::new(&encrypted);
        let recovered_filename =
            decrypt_file_wks(&master_key, &mut enc_reader, &mut decrypted)
                .expect("keystore decryption failed");

        assert_eq!(recovered_filename, original_filename);
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_invalid_magic_bytes_rejected() {
        let mut corrupt_data = vec![b'X', b'X', b'X', b'X'];
        corrupt_data.extend_from_slice(&[1, 1, 1, 0, 1, 0]);

        let result = read_file_header(&mut Cursor::new(corrupt_data));
        assert!(result.is_err());
        match result {
            Err(CryptError::InvalidHeader(msg)) => {
                assert!(msg.contains("Invalid magic bytes"));
            }
            other => panic!("Expected CryptError::InvalidHeader, got {:?}", other),
        }
    }

    #[test]
    fn test_unsupported_format_version_rejected() {
        let mut invalid_version = Vec::new();
        invalid_version.extend_from_slice(MAGIC_BYTES);
        invalid_version.push(99); // Unsupported format version 99
        invalid_version.extend_from_slice(&[1, 1, 0, 1, 0]);

        let result = read_file_header(&mut Cursor::new(invalid_version));
        assert!(result.is_err());
        match result {
            Err(CryptError::InvalidHeader(msg)) => {
                assert!(msg.contains("Unsupported format version 99"));
            }
            other => panic!("Expected CryptError::InvalidHeader, got {:?}", other),
        }
    }

    #[test]
    fn test_mode_mismatch_rejected() {
        let master_key = [7u8; 32];
        let original_data = b"secret data";

        let mut encrypted = Vec::new();
        encrypt_file_wks(
            &master_key,
            "test.txt",
            &mut Cursor::new(original_data),
            &mut encrypted,
            64,
        )
        .unwrap();

        // Attempting to decrypt keystore-encrypted file with password decryptor
        let mut enc_reader = Cursor::new(&encrypted);
        let mut out = Vec::new();
        let result = decrypt_file_with_pwd("password", &mut enc_reader, &mut out);
        assert!(result.is_err());
        match result {
            Err(CryptError::InvalidHeader(msg)) => {
                assert!(msg.contains("Expected password encryption mode"));
            }
            other => panic!("Expected CryptError::InvalidHeader, got {:?}", other),
        }
    }
}
