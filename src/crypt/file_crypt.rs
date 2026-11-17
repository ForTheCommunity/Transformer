use std::io::{self, Read, Write};

use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};

use crate::crypt::{
    errors::CryptError,
    zeroize::{Zeroize, Zeroizing},
};

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

pub const MIN_CHUNK_SIZE: usize = 1024; // 1 KB
pub const MAX_CHUNK_SIZE: usize = 100 * 1024 * 1024; // 100 MB
pub const AES_GCM_TAG_SIZE: usize = 16;
pub const MAX_CIPHERTEXT_CHUNK_SIZE: usize = MAX_CHUNK_SIZE + AES_GCM_TAG_SIZE + 4096;

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

impl FileHeader {
    pub fn to_bytes(&self) -> [u8; 10] {
        let mut buf = [0u8; 10];
        buf[0..4].copy_from_slice(MAGIC_BYTES);
        buf[4] = self.format_version;
        buf[5] = self.mode as u8;
        buf[6] = self.cipher_suite as u8;
        buf[7..10].copy_from_slice(&self.tool_version);
        buf
    }
}

// Write the common header bytes into the writer.
pub fn write_header(
    writer: &mut impl Write,
    mode: EncryptionMode,
    cipher_suite: CipherSuite,
) -> Result<(), CryptError> {
    let header = FileHeader {
        format_version: CURRENT_FORMAT_VERSION,
        mode,
        cipher_suite,
        tool_version: CURRENT_TOOL_VERSION,
    };
    writer.write_all(&header.to_bytes()).map_err(io_err)?;
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

#[inline]
fn io_err(e: io::Error) -> CryptError {
    CryptError::Error("I/O error".to_string(), e.to_string())
}

// Read from reader until buf is full or EOF is reached.
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

// Derive a per-chunk nonce from a 12-byte `base_nonce` and a 64-bit chunk counter.
fn chunk_nonce(base_nonce: &[u8; 12], counter: u64) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let counter_bytes = counter.to_le_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= counter_bytes[i];
    }
    nonce
}

/// Sanitizes a filename from the encrypted header to prevent Directory Traversal attacks.
pub fn sanitize_filename(raw_name: &str) -> Result<String, CryptError> {
    crate::util::sanitize_filename(raw_name).ok_or_else(|| {
        CryptError::InvalidHeader("Invalid or unsafe filename in header".to_string())
    })
}

// Encrypt all bytes from `input` into `writer` in `chunk_size`-byte blocks.
fn stream_encrypt(
    cipher: &Aes256Gcm,
    base_nonce: &[u8; 12],
    input: &mut impl Read,
    writer: &mut impl Write,
    chunk_size: usize,
) -> Result<(), CryptError> {
    let effective_chunk_size = chunk_size.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);
    let mut buf = vec![0u8; effective_chunk_size];
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

        if n < effective_chunk_size {
            break; // EOF reached
        }
    }

    // End-of-stream sentinel: a zero-length chunk.
    writer.write_all(&0u32.to_le_bytes()).map_err(io_err)?;
    writer.flush().map_err(io_err)
}

// Decrypt all length-prefixed ciphertext chunks from `reader` into `writer`.
fn stream_decrypt(
    cipher: &Aes256Gcm,
    base_nonce: &[u8; 12],
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<String, CryptError> {
    let mut counter: u64 = 0;
    let mut hdr_buf: Vec<u8> = Vec::new();
    let mut filename: Option<String> = None;

    loop {
        // Read the 4-byte chunk length prefix.
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(CryptError::InvalidHeader(
                    "Ciphertext stream unexpectedly truncated before EOF sentinel".to_string(),
                ));
            }
            Err(e) => return Err(io_err(e)),
        }
        let ct_len = u32::from_le_bytes(len_buf) as usize;

        if ct_len == 0 {
            // Check that no trailing data exists after the sentinel
            let mut trailing = [0u8; 1];
            match reader.read(&mut trailing) {
                Ok(0) => break,
                Ok(_) => {
                    return Err(CryptError::InvalidHeader(
                        "Unexpected trailing bytes detected after EOF sentinel".to_string(),
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(io_err(e)),
            }
        }

        if !(AES_GCM_TAG_SIZE..=MAX_CIPHERTEXT_CHUNK_SIZE).contains(&ct_len) {
            return Err(CryptError::InvalidHeader(format!(
                "Ciphertext chunk length ({ct_len} bytes) is out of bounds (min {AES_GCM_TAG_SIZE} B, max {MAX_CIPHERTEXT_CHUNK_SIZE} B)"
            )));
        }

        // Read and decrypt the ciphertext chunk.
        let mut ct = vec![0u8; ct_len];
        match reader.read_exact(&mut ct) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(CryptError::InvalidHeader(
                    "Ciphertext stream truncated inside chunk payload".to_string(),
                ));
            }
            Err(e) => return Err(io_err(e)),
        }

        let nonce = Nonce::from(chunk_nonce(base_nonce, counter));
        let decrypted = cipher.decrypt(&nonce, ct.as_slice()).map_err(|e| {
            CryptError::AesGcmError(
                format!("Failed to decrypt chunk {counter} (corrupted or tampered data)"),
                e.to_string(),
            )
        })?;

        counter += 1;

        // Extract filename header (runs only for the first chunk(s))
        if filename.is_none() {
            hdr_buf.extend_from_slice(&decrypted);

            if hdr_buf.len() >= 4 {
                let name_len = u32::from_le_bytes(hdr_buf[0..4].try_into().unwrap()) as usize;
                if name_len == 0 || name_len > 4096 {
                    return Err(CryptError::InvalidHeader(format!(
                        "Invalid filename length ({name_len} bytes) in header"
                    )));
                }
                let hdr_end = 4 + name_len;

                if hdr_buf.len() >= hdr_end {
                    let raw_filename = String::from_utf8(hdr_buf[4..hdr_end].to_vec()).map_err(
                        |e| {
                            CryptError::Error(
                                "Filename contains invalid UTF-8".to_string(),
                                e.to_string(),
                            )
                        },
                    )?;

                    filename = Some(sanitize_filename(&raw_filename)?);

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
            String::new(),
        )
    })
}

// ─── keystore-based encrypt / decrypt ────────────────────────────────────────

pub fn encrypt_file_wks(
    master_key: &[u8; 32],
    filename: &str,
    reader: &mut impl Read,
    writer: &mut impl Write,
    chunk_size: usize,
) -> Result<(), CryptError> {
    // Master KEK cipher
    let kek = Key::<Aes256Gcm>::from(*master_key);
    let master_cipher = Aes256Gcm::new(&kek);

    // Per-file DEK
    let mut file_dek = Zeroizing([0u8; 32]);
    rand::fill(&mut *file_dek);

    let header = FileHeader {
        format_version: CURRENT_FORMAT_VERSION,
        mode: EncryptionMode::Keystore,
        cipher_suite: CipherSuite::Aes256Gcm,
        tool_version: CURRENT_TOOL_VERSION,
    };
    let header_bytes = header.to_bytes();

    // Wrap DEK with master key (KEK) using header bytes as AAD
    let mut dek_nonce_bytes = [0u8; 12];
    rand::fill(&mut dek_nonce_bytes);
    let wrapped_dek = master_cipher
        .encrypt(
            &Nonce::from(dek_nonce_bytes),
            Payload {
                msg: file_dek.as_ref(),
                aad: &header_bytes,
            },
        )
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
    writer.write_all(&header_bytes).map_err(io_err)?;
    writer.write_all(&dek_nonce_bytes).map_err(io_err)?;
    writer
        .write_all(&(wrapped_dek.len() as u32).to_le_bytes())
        .map_err(io_err)?;
    writer.write_all(&wrapped_dek).map_err(io_err)?;
    writer.write_all(&base_nonce).map_err(io_err)?;

    // Build file DEK cipher
    let file_key = Key::<Aes256Gcm>::from(*file_dek);
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

pub fn decrypt_file_wks(
    master_key: &[u8; 32],
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<String, CryptError> {
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
    let header_bytes = header.to_bytes();

    let kek = Key::<Aes256Gcm>::from(*master_key);
    let master_cipher = Aes256Gcm::new(&kek);

    let mut dek_nonce_bytes = [0u8; 12];
    reader.read_exact(&mut dek_nonce_bytes).map_err(io_err)?;

    let mut dek_len_buf = [0u8; 4];
    reader.read_exact(&mut dek_len_buf).map_err(io_err)?;
    let dek_len = u32::from_le_bytes(dek_len_buf) as usize;

    if !(AES_GCM_TAG_SIZE..=1024).contains(&dek_len) {
        return Err(CryptError::InvalidHeader(format!(
            "Wrapped DEK length ({dek_len} bytes) is invalid"
        )));
    }

    let mut wrapped_dek = vec![0u8; dek_len];
    reader.read_exact(&mut wrapped_dek).map_err(io_err)?;

    let mut base_nonce = [0u8; 12];
    reader.read_exact(&mut base_nonce).map_err(io_err)?;

    // Unwrap DEK verifying header as AAD
    let mut file_dek_vec = master_cipher
        .decrypt(
            &Nonce::from(dek_nonce_bytes),
            Payload {
                msg: wrapped_dek.as_ref(),
                aad: &header_bytes,
            },
        )
        .map_err(|e| {
            CryptError::AesGcmError(
                "Error occurred while decrypting DEK Key of file using master password".to_string(),
                e.to_string(),
            )
        })?;

    let file_dek: [u8; 32] = file_dek_vec.as_slice().try_into().map_err(|_| {
        CryptError::Error(
            "Decrypted DEK must be exactly 32 bytes".to_string(),
            String::new(),
        )
    })?;
    file_dek_vec.zeroize();

    let file_key = Key::<Aes256Gcm>::from(file_dek);
    let file_cipher = Aes256Gcm::new(&file_key);

    stream_decrypt(&file_cipher, &base_nonce, reader, writer)
}

// ─── password-based encrypt / decrypt ────────────────────────────────────────

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
    let salt_string = argon2::password_hash::SaltString::encode_b64(&salt_bytes).map_err(|e| {
        CryptError::Argon2Error("Unable to generate Salt String".to_string(), e.to_string())
    })?;
    let kek_bytes = crate::crypt::keystore::derive_kek(password, salt_string.as_str())?;
    let kek = Key::<Aes256Gcm>::from(*kek_bytes);
    let master_cipher = Aes256Gcm::new(&kek);

    // Per-file DEK
    let mut file_dek = Zeroizing([0u8; 32]);
    rand::fill(&mut *file_dek);

    let header = FileHeader {
        format_version: CURRENT_FORMAT_VERSION,
        mode: EncryptionMode::Password,
        cipher_suite: CipherSuite::Aes256Gcm,
        tool_version: CURRENT_TOOL_VERSION,
    };
    let header_bytes = header.to_bytes();

    // Authenticated Associated Data: header + salt
    let mut aad = [0u8; 26];
    aad[0..10].copy_from_slice(&header_bytes);
    aad[10..26].copy_from_slice(&salt_bytes);

    // Wrap DEK with KEK
    let mut dek_nonce_bytes = [0u8; 12];
    rand::fill(&mut dek_nonce_bytes);
    let wrapped_dek = master_cipher
        .encrypt(
            &Nonce::from(dek_nonce_bytes),
            Payload {
                msg: file_dek.as_ref(),
                aad: &aad,
            },
        )
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
    writer.write_all(&header_bytes).map_err(io_err)?;
    writer.write_all(&salt_bytes).map_err(io_err)?;
    writer.write_all(&dek_nonce_bytes).map_err(io_err)?;
    writer
        .write_all(&(wrapped_dek.len() as u32).to_le_bytes())
        .map_err(io_err)?;
    writer.write_all(&wrapped_dek).map_err(io_err)?;
    writer.write_all(&base_nonce).map_err(io_err)?;

    // Build file DEK cipher
    let file_key = Key::<Aes256Gcm>::from(*file_dek);
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

pub fn decrypt_file_with_pwd(
    password: &str,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<String, CryptError> {
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
    let header_bytes = header.to_bytes();

    // Read salt and re-derive KEK
    let mut salt_bytes = [0u8; 16];
    reader.read_exact(&mut salt_bytes).map_err(io_err)?;
    let salt_string =
        argon2::password_hash::SaltString::encode_b64(&salt_bytes).map_err(|e| {
            CryptError::Argon2Error(
                "Error occurred while encoding salt bytes to salt string".to_string(),
                e.to_string(),
            )
        })?;
    let kek_bytes = crate::crypt::keystore::derive_kek(password, salt_string.as_str())?;
    let kek = Key::<Aes256Gcm>::from(*kek_bytes);
    let master_cipher = Aes256Gcm::new(&kek);

    let mut dek_nonce_bytes = [0u8; 12];
    reader.read_exact(&mut dek_nonce_bytes).map_err(io_err)?;

    let mut dek_len_buf = [0u8; 4];
    reader.read_exact(&mut dek_len_buf).map_err(io_err)?;
    let dek_len = u32::from_le_bytes(dek_len_buf) as usize;

    if !(AES_GCM_TAG_SIZE..=1024).contains(&dek_len) {
        return Err(CryptError::InvalidHeader(format!(
            "Wrapped DEK length ({dek_len} bytes) is invalid"
        )));
    }

    let mut wrapped_dek = vec![0u8; dek_len];
    reader.read_exact(&mut wrapped_dek).map_err(io_err)?;

    let mut base_nonce = [0u8; 12];
    reader.read_exact(&mut base_nonce).map_err(io_err)?;

    // Authenticated Associated Data: header + salt
    let mut aad = [0u8; 26];
    aad[0..10].copy_from_slice(&header_bytes);
    aad[10..26].copy_from_slice(&salt_bytes);

    // Unwrap DEK
    let mut file_dek_vec = master_cipher
        .decrypt(
            &Nonce::from(dek_nonce_bytes),
            Payload {
                msg: wrapped_dek.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|e| {
            CryptError::AesGcmError(
                "Failed to unwrap file DEK (Incorrect password or corrupted payload)".to_string(),
                e.to_string(),
            )
        })?;

    let file_dek: [u8; 32] = file_dek_vec.as_slice().try_into().map_err(|_| {
        CryptError::Error(
            "Decrypted DEK must be exactly 32 bytes".to_string(),
            String::new(),
        )
    })?;
    file_dek_vec.zeroize();

    let file_key = Key::<Aes256Gcm>::from(file_dek);
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
            16,
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

        let mut enc_cursor = Cursor::new(&encrypted);
        let header = read_file_header(&mut enc_cursor).expect("failed to read header");
        assert_eq!(header.format_version, CURRENT_FORMAT_VERSION);
        assert_eq!(header.mode, EncryptionMode::Keystore);
        assert_eq!(header.cipher_suite, CipherSuite::Aes256Gcm);

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

    #[test]
    fn test_path_traversal_filename_sanitized() {
        let password = "TestPassword999!";
        let malicious_filename = "../../../../etc/shadow";
        let data = b"root:x:0:0:root:/root:/bin/bash";

        let mut encrypted = Vec::new();
        encrypt_file_with_pwd(
            password,
            malicious_filename,
            &mut Cursor::new(data),
            &mut encrypted,
            128,
        )
        .expect("encryption failed");

        let mut decrypted = Vec::new();
        let mut enc_reader = Cursor::new(&encrypted);
        let recovered_filename =
            decrypt_file_with_pwd(password, &mut enc_reader, &mut decrypted)
                .expect("decryption failed");

        assert_eq!(recovered_filename, "shadow");
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_tampered_header_fails_auth() {
        let password = "TestPassword999!";
        let mut encrypted = Vec::new();
        encrypt_file_with_pwd(
            password,
            "file.txt",
            &mut Cursor::new(b"hello world"),
            &mut encrypted,
            128,
        )
        .expect("encryption failed");

        // Tamper with tool version in header (byte index 7)
        encrypted[7] ^= 0xFF;

        let mut decrypted = Vec::new();
        let mut enc_reader = Cursor::new(&encrypted);
        let result = decrypt_file_with_pwd(password, &mut enc_reader, &mut decrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_stream_rejected() {
        let password = "TestPassword999!";
        let mut encrypted = Vec::new();
        encrypt_file_with_pwd(
            password,
            "file.txt",
            &mut Cursor::new(b"hello world"),
            &mut encrypted,
            128,
        )
        .expect("encryption failed");

        // Truncate last 10 bytes
        encrypted.truncate(encrypted.len() - 10);

        let mut decrypted = Vec::new();
        let mut enc_reader = Cursor::new(&encrypted);
        let result = decrypt_file_with_pwd(password, &mut enc_reader, &mut decrypted);
        assert!(result.is_err());
    }
}
