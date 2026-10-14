use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};

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
