use std::{fs, path::PathBuf};

use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::crypt::errors::CryptError;

const CURRENT_KEYSTORE_VERSION: u8 = 1;
#[derive(Serialize, Deserialize)]
pub struct KeyStore {
    pub version: u8,
    pub salt: String,
    pub nonce: String,
    pub wrapped_key: String,
}

// Deriving a 32-Byte (256 Bit) Key Encryption Key (KEK) from user password + salt.
pub fn derive_kek(password: &str, salt_str: &str) -> Result<[u8; 32], CryptError> {
    let salt = SaltString::from_b64(salt_str).map_err(|e| {
        CryptError::Argon2Error(
            "Error occurred while generating salt from B64 salt str".to_string(),
            e.to_string(),
        )
    })?;
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| {
            CryptError::Argon2Error(
                "Error occurred while generating password hash".to_string(),
                e.to_string(),
            )
        })?;

    // Extracting raw hash bytes to use as AES Key...
    let hash_bytes = password_hash.hash.ok_or(CryptError::Argon2Error(
        "Error occurred while extracting raw hash bytes from password hash !!!".to_string(),
        "".to_string(),
    ))?;

    let mut key = [0u8; 32];
    let bytes_to_copy = std::cmp::min(hash_bytes.as_bytes().len(), 32);
    key[..bytes_to_copy].copy_from_slice(&hash_bytes.as_bytes()[..bytes_to_copy]);
    Ok(key)
}

// this creates a keystore ( creates single-key keystore ).
pub fn create_keystore(path: &PathBuf, password: &str) -> Result<(), CryptError> {
    // Genereating random salt for argon2.
    let mut salt_bytes = [0u8; 16];
    rand::fill(&mut salt_bytes);
    let salt_string = SaltString::encode_b64(&salt_bytes).map_err(|e| {
        CryptError::Argon2Error(
            "Error occurred while generating salt from B64 salt str".to_string(),
            e.to_string(),
        )
    })?;

    // Derive KEK from password....
    let kek_bytes = derive_kek(password, salt_string.as_str())?;
    let kek = Key::<Aes256Gcm>::try_from(kek_bytes).map_err(|e| {
        CryptError::AesGcmError(
            "Error occurred while deriving KEK".to_string(),
            e.to_string(),
        )
    })?;
    let cipher = Aes256Gcm::new(&kek);

    // Generate the Master Key that will be used to wrap/unwrap per-file DEKs.
    let mut master_key_bytes = [0u8; 32];
    rand::fill(&mut master_key_bytes);

    // Encrypt the Master Key using the KEK.
    let mut nonce_bytes = [0u8; 12]; // 96 bits for AES-GCM
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let encrypted_master_key = cipher
        .encrypt(&nonce, master_key_bytes.as_ref())
        .map_err(|e| {
            CryptError::AesGcmError(
                "Error occurred while encyrpting Master Key".to_string(),
                e.to_string(),
            )
        })?;

    // saving Keystore as a JSON file.
    let keystore = KeyStore {
        version: CURRENT_KEYSTORE_VERSION,
        salt: salt_string.to_string(),
        nonce: STANDARD.encode(nonce),
        wrapped_key: STANDARD.encode(encrypted_master_key),
    };

    let json_data = serde_json::to_string_pretty(&keystore).map_err(|e| {
        CryptError::SerdeError(
            "Error Serealizing Keystore JSON data".to_string(),
            e.to_string(),
        )
    })?;

    fs::write(path, json_data)
        .map_err(|e| CryptError::Error("Error saving Keystore file".to_string(), e.to_string()))?;

    Ok(())
}

pub fn load_keystore_key(path: &PathBuf, password: &str) -> Result<[u8; 32], CryptError> {
    let json_data = fs::read_to_string(path)
        .map_err(|e| CryptError::Error("Unable to load keystore file".to_string(), e.to_string()))?;
    let keystore = serde_json::from_str::<KeyStore>(&json_data).map_err(|e| {
        CryptError::SerdeError("Unable to Deserealize Keystore".to_string(), e.to_string())
    })?;

    // Re-derive KEK from the user-provided password and saved salt.
    let kek_bytes = derive_kek(password, &keystore.salt)?;
    let kek = Key::<Aes256Gcm>::try_from(kek_bytes)
        .map_err(|e| CryptError::AesGcmError("Invalid Key Length".to_string(), e.to_string()))?;
    let cipher = Aes256Gcm::new(&kek);

    // Decode nonce & wrapped key.
    let nonce_bytes = STANDARD
        .decode(&keystore.nonce)
        .map_err(|e| CryptError::B64Error("Error decoding Nonce".to_string(), e.to_string()))?;
    let nonce = aes_gcm::Nonce::try_from(nonce_bytes.as_slice())
        .map_err(|e| CryptError::AesGcmError("Error decoding Nonce".to_string(), e.to_string()))?;
    let encrypted_master_key = STANDARD.decode(&keystore.wrapped_key).map_err(|e| {
        CryptError::B64Error("Error decoding Wrapped Key".to_string(), e.to_string())
    })?;

    // Decrypt to retrive the actual master key
    let master_key_vec = cipher
        .decrypt(&nonce, encrypted_master_key.as_ref())
        .map_err(|e| {
            CryptError::AesGcmError(
                "Incorrect password or corrupted keystore".to_string(),
                e.to_string(),
            )
        })?;

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&master_key_vec);

    Ok(master_key)
}
