use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

use crate::crypt::errors::CryptError;

// encrypts file/s with keystore
pub fn encrypt_file_wks(
    master_key: &[u8; 32],
    filename: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptError> {
    let key = Key::<Aes256Gcm>::try_from(master_key.clone()).map_err(|e| {
        CryptError::AesGcmError(
            "Error Generating Key from Master Key".to_string(),
            e.to_string(),
        )
    })?;
    let master_cipher = Aes256Gcm::new(&key);

    // filename and filedata
    let filename_bytes = filename.as_bytes();
    let filename_len = filename.len() as u32;

    let mut raw_plaintext = Vec::new();
    raw_plaintext.extend_from_slice(&filename_len.to_le_bytes());
    raw_plaintext.extend_from_slice(filename_bytes);
    raw_plaintext.extend_from_slice(plaintext);

    // generating a new DEK
    let mut file_dek = [0u8; 32];
    rand::fill(&mut file_dek);

    // Encrypting using DEK
    let file_cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::try_from(file_dek).map_err(|e| {
        CryptError::AesGcmError("Error generating Key from DEK".to_string(), e.to_string())
    })?);
    let mut file_nonce_bytes = [0u8; 12];
    rand::fill(&mut file_nonce_bytes);
    let file_nonce = Nonce::from(file_nonce_bytes);
    let encrypted_file = file_cipher
        .encrypt(&file_nonce, raw_plaintext.as_ref())
        .map_err(|e| {
            CryptError::AesGcmError(
                "Error occurred while encrypting file".to_string(),
                e.to_string(),
            )
        })?;

    // Encrypting per-file DEK Key using Master Key (KEK)..
    let mut dek_nonce_bytes = [0u8; 12];
    rand::fill(&mut dek_nonce_bytes);
    let dek_nonce = Nonce::from(dek_nonce_bytes);
    let encrypted_dek_key = master_cipher
        .encrypt(&dek_nonce, file_dek.as_ref())
        .map_err(|e| {
            CryptError::AesGcmError(
                "Error occurred while encrypting file DEK Key".to_string(),
                e.to_string(),
            )
        })?;

    // merging encrypted dek key with encrypted file content.
    let mut payload = Vec::new();
    payload.extend_from_slice(&dek_nonce); // 12 bytes
    payload.extend_from_slice(&(encrypted_dek_key.len() as u32).to_le_bytes()); // 4 bytes for length
    payload.extend_from_slice(&encrypted_dek_key); // Variable length
    payload.extend_from_slice(&file_nonce); // 12 bytes
    payload.extend_from_slice(&encrypted_file); // Variable length

    // Payload => [ DEK Nonce (12B) ] + [ Wrapped DEK Len (4B) ] + [ Wrapped DEK ] +
    // [ File Nonce (12B) ] + [ Encrypted (Filename Len + Filename + File Bytes) ]

    Ok(payload)
}

// decrypt file/s with keystore
pub fn decrypt_file_wks(
    master_key: &[u8; 32],
    payload: &[u8],
) -> Result<(String, Vec<u8>), CryptError> {
    let key = Key::<Aes256Gcm>::try_from(master_key.clone()).map_err(|e| {
        CryptError::AesGcmError(
            "Error Generating Key from Master Key".to_string(),
            e.to_string(),
        )
    })?;
    let master_cipher = Aes256Gcm::new(&key);

    if payload.len() < 28 {
        return Err(CryptError::AesGcmError(
            "Encrypted Payload is too short or corrupted !!!".to_string(),
            "".to_string(),
        ));
    }

    let mut cursor = 0;

    // extracting DEK Nonce...
    let dek_nonce_bytes: &[u8; 12] = payload[cursor..cursor + 12]
        .try_into()
        .map_err(|_| CryptError::Error("Invalid DEK nonce length".to_string(), "".to_string()))?;
    let dek_nonce = Nonce::from(*dek_nonce_bytes);
    cursor += 12;

    // EXtracting DEK Length.
    let dek_length = u32::from_le_bytes(payload[cursor..cursor + 4].try_into().map_err(|_| {
        CryptError::Error(
            "Error occurred while extracting DEK Length...".to_string(),
            "".to_string(),
        )
    })?) as usize;
    cursor += 4;

    // Extracting Encrypted DEK
    let encrypted_dek_end = cursor + dek_length;
    if payload.len() < encrypted_dek_end + 12 {
        return Err(CryptError::AesGcmError(
            "Error extracting encrypted DEK, Payload is too short, may be corrupted !!!"
                .to_string(),
            "".to_string(),
        ));
    }
    let encrypted_dek = &payload[cursor..encrypted_dek_end];
    cursor = encrypted_dek_end;

    // Extracting file nonce.
    let file_nonce_bytes: &[u8; 12] = payload[cursor..cursor + 12].try_into().map_err(|_| {
        CryptError::AesGcmError(
            "Error occurred while extracting DEK Length...".to_string(),
            "".to_string(),
        )
    })?;
    let file_nonce = Nonce::from(*file_nonce_bytes);
    cursor += 12;

    // Extracting Encrypted File Data.
    let encrypted_file = &payload[cursor..];

    // Decrypting DEK Key using master key.
    let file_dec_vec = master_cipher
        .decrypt(&dek_nonce, encrypted_dek)
        .map_err(|e| {
            CryptError::AesGcmError(
                "Error occurred while decrypting DEK Key of file using master password".to_string(),
                e.to_string(),
            )
        })?;
    let file_dek_bytes: [u8; 32] = file_dec_vec.try_into().map_err(|_| {
        CryptError::Error(
            "Decrypted DEK must be exactly 32 bytes".to_string(),
            "".to_string(),
        )
    })?;
    let file_dek_key = Key::<Aes256Gcm>::try_from(file_dek_bytes).unwrap();

    // Decrypting file data using dek key.
    let file_cipher = Aes256Gcm::new(&file_dek_key);
    let raw_data = file_cipher
        .decrypt(&file_nonce, encrypted_file)
        .map_err(|e| {
            CryptError::AesGcmError(
                "Failed to decrypt file contents, file has been corrupted or Tampered Data)"
                    .to_string(),
                e.to_string(),
            )
        })?;

    if raw_data.len() < 4 {
        return Err(CryptError::Error(
            "Decrypted file structure is invalid".to_string(),
            "".to_string(),
        ));
    }

    // extracting file name..
    let filename_len = u32::from_le_bytes(raw_data[0..4].try_into().map_err(|_e| {
        CryptError::Error(
            "Invalid filename length.".to_string(),
            "Error occurred while extracting filename length".to_string(),
        )
    })?) as usize;
    let file_name = String::from_utf8(raw_data[4..4 + filename_len].to_vec()).map_err(|_e| {
        CryptError::Error(
            "Problem occurred while extracting filename..".to_string(),
            "".to_string(),
        )
    })?;
    let file_data = raw_data[4 + filename_len..].to_vec();

    Ok((file_name, file_data))
}

// Derive KEK directly from a password & a given salt.
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
    let bytes_to_copy = std::cmp::min(hash_bytes.as_bytes().len(), 32);
    key[..bytes_to_copy].copy_from_slice(&hash_bytes.as_bytes()[..bytes_to_copy]);

    Ok(key)
}

// encrypt file with password
// Payload :
// [ Salt (16B) ] + [ DEK Nonce (12B) ] + [ Wrapped DEK Len (4B) ] +
// [ Wrapped DEK ] + [ File Nonce (12B) ] + [ Encrypted Data ]
pub fn encrypt_file_with_pwd(
    password: &str,
    filename: &str,
    file_data: &[u8],
) -> Result<Vec<u8>, CryptError> {
    // Generate Fresh new random salt
    let mut salt_bytes = [0u8; 16];
    rand::fill(&mut salt_bytes);
    let salt_string = SaltString::encode_b64(&salt_bytes).map_err(|e| {
        CryptError::Argon2Error("Unable to generate Salt String".to_string(), e.to_string())
    })?;

    // Deriving KEK Directly using Password + Salt.
    let kek_bytes = derive_kek_from_pwd(password, salt_string.as_str())?;
    let key = Key::<Aes256Gcm>::try_from(kek_bytes).map_err(|e| {
        CryptError::AesGcmError(
            "Error ocurred generating Key from KEK Bytes".to_string(),
            e.to_string(),
        )
    })?;
    let master_cipher = Aes256Gcm::new(&key);

    // File data
    let filename_bytes = filename.as_bytes();
    let filename_len = filename_bytes.len() as u32;

    let mut raw_file_data = Vec::new();
    raw_file_data.extend_from_slice(&filename_len.to_le_bytes());
    raw_file_data.extend_from_slice(filename_bytes);
    raw_file_data.extend_from_slice(file_data);

    // New Random Per-File DEK Key
    let mut file_dek = [0u8; 32];
    rand::fill(&mut file_dek);

    // Encrypting file data using the per-file DEK
    let key = Key::<Aes256Gcm>::try_from(file_dek).map_err(|e| {
        CryptError::AesGcmError(
            "Error ocurred generating Key from DEK Bytes".to_string(),
            e.to_string(),
        )
    })?;
    let file_cipher = Aes256Gcm::new(&key);
    let mut file_nonce_bytes = [0u8; 12];
    rand::fill(&mut file_nonce_bytes);

    let file_nonce = Nonce::from(file_nonce_bytes);
    let encrypted_file = file_cipher
        .encrypt(&file_nonce, raw_file_data.as_ref())
        .map_err(|e| {
            CryptError::AesGcmError(
                "Error occurred while encrypting file".to_string(),
                e.to_string(),
            )
        })?;

    // Encrypting Per-File DEK Key using KEK Key derived from password.
    let mut dek_nonce_bytes = [0u8; 12];
    rand::fill(&mut dek_nonce_bytes);
    let dek_nonce = Nonce::from(dek_nonce_bytes);
    let wrapped_dek = master_cipher
        .encrypt(&dek_nonce, file_dek.as_ref())
        .map_err(|e| {
            CryptError::AesGcmError(
                "Error occurred encrypting DEK Key using password-derived KEK".to_string(),
                e.to_string(),
            )
        })?;

    // To keep binary layout clean, let's store raw 16-byte salt:
    // Let's rewrite salt storage as raw 16 bytes:
    // Actually, let's keep it simple: SaltString base64 can vary, so let's use raw 16 bytes for the header:
    let mut final_payload = Vec::new();
    final_payload.extend_from_slice(&salt_bytes); // 16 bytes raw salt
    final_payload.extend_from_slice(&dek_nonce); // 12 bytes
    final_payload.extend_from_slice(&(wrapped_dek.len() as u32).to_le_bytes()); // 4 bytes
    final_payload.extend_from_slice(&wrapped_dek); // variable length
    final_payload.extend_from_slice(&file_nonce); // 12 bytes
    final_payload.extend_from_slice(&encrypted_file); // variable length

    Ok(final_payload)
}

// decrypt file with password
pub fn decrypt_file_with_pwd(
    password: &str,
    payload: &[u8],
) -> Result<(String, Vec<u8>), CryptError> {
    if payload.len() < 44 {
        // 16 (salt) + 12 (dek_nonce) + 4 (len) + min_dek + 12 (file_nonce)
        return Err(CryptError::Error(
            "Encrypted payload is too short or corrupted".to_string(),
            "".to_string(),
        ));
    }

    let mut cursor = 0;

    // Extract Raw 16-byte Salt
    let salt_bytes: [u8; 16] = payload[cursor..cursor + 16].try_into().map_err(|_| {
        CryptError::Error(
            "Error occurred while extracting salt bytes form encrypted file.".to_string(),
            "".to_string(),
        )
    })?;
    cursor += 16;
    let salt_string = SaltString::encode_b64(&salt_bytes).map_err(|e| {
        CryptError::Argon2Error(
            "Error occurred while encoding salt bytes to salt string".to_string(),
            e.to_string(),
        )
    })?;

    // Re-derive KEK from password + extracted salt
    let kek_bytes = derive_kek_from_pwd(password, salt_string.as_str())?;
    let key = Key::<Aes256Gcm>::try_from(kek_bytes).map_err(|e| {
        CryptError::AesGcmError(
            "Error ocurred generating Key from KEK Bytes".to_string(),
            e.to_string(),
        )
    })?;
    let master_cipher = Aes256Gcm::new(&key);

    // Extract DEK Nonce
    let dek_nonce = Nonce::try_from(&payload[cursor..cursor + 12])
        .map_err(|e| CryptError::Error("Unable to extract DEK Nonce".to_string(), e.to_string()))?;
    cursor += 12;

    // Extract Wrapped DEK Length
    let dek_len = u32::from_le_bytes(payload[cursor..cursor + 4].try_into().map_err(|_| {
        CryptError::Error("Unable to extract DEK Length".to_string(), "".to_string())
    })?) as usize;
    cursor += 4;

    // Extract Wrapped DEK
    let wrapped_dek_end = cursor + dek_len;
    if payload.len() < wrapped_dek_end + 12 {
        return Err(CryptError::Error(
            "Payload corrupted during DEK extraction".to_string(),
            "".to_string(),
        ));
    }
    let wrapped_dek = &payload[cursor..wrapped_dek_end];
    cursor = wrapped_dek_end;

    // Extract File Nonce
    let file_nonce = Nonce::try_from(&payload[cursor..cursor + 12]).map_err(|e| {
        CryptError::Error("Unable to extract file nonce".to_string(), e.to_string())
    })?;
    cursor += 12;

    // Extract Encrypted File Data
    let encrypted_file = &payload[cursor..];

    // Decrypt the Per-File DEK using KEK
    let file_dek_vec = master_cipher
        .decrypt(&dek_nonce, wrapped_dek)
        .map_err(|e| {
            CryptError::AesGcmError(
                "Failed to unwrap file DEK (Incorrect password or corrupted payload)".to_string(),
                e.to_string(),
            )
        })?;

    let file_dek = Key::<Aes256Gcm>::try_from(file_dek_vec.as_slice()).map_err(|e| {
        CryptError::AesGcmError("Unable to get file DEK key".to_string(), e.to_string())
    })?;

    // Decrypt inner file data
    let file_cipher = Aes256Gcm::new(&file_dek);
    let raw_plaintext = file_cipher
        .decrypt(&file_nonce, encrypted_file)
        .map_err(|e| {
            CryptError::AesGcmError(
                "Failed to decrypt file contents (Corrupted or tampered data)".to_string(),
                e.to_string(),
            )
        })?;

    // Unframe filename and file bytes
    if raw_plaintext.len() < 4 {
        return Err(CryptError::Error(
            "Decrypted file structure is invalid".to_string(),
            "".to_string(),
        ));
    }

    let filename_len = u32::from_le_bytes(raw_plaintext[0..4].try_into().map_err(|_| {
        CryptError::Error("Unable to extract filename...".to_string(), "".to_string())
    })?) as usize;
    if raw_plaintext.len() < 4 + filename_len {
        return Err(CryptError::Error(
            "Decrypted filename length mismatch".to_string(),
            "".to_string(),
        ));
    }

    let filename = String::from_utf8(raw_plaintext[4..4 + filename_len].to_vec())
        .map_err(|e| CryptError::Error("".to_string(), e.to_string()))?;
    let file_data = raw_plaintext[4 + filename_len..].to_vec();

    Ok((filename, file_data))
}
