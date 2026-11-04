use std::{fs, path::Path};

use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::crypt::{
    errors::CryptError,
    zeroize::{Zeroize, Zeroizing},
};

const CURRENT_KEYSTORE_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
pub struct KeyStore {
    pub version: u8,
    pub salt: String,
    pub nonce: String,
    pub wrapped_key: String,
}

/// Deriving a 32-Byte (256-bit) Key Encryption Key (KEK) from user password + salt.
pub fn derive_kek(password: &str, salt_str: &str) -> Result<Zeroizing<[u8; 32]>, CryptError> {
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

    // Extracting raw hash bytes to use as AES Key
    let hash_bytes = password_hash.hash.ok_or_else(|| {
        CryptError::Argon2Error(
            "Error occurred while extracting raw hash bytes from password hash".to_string(),
            String::new(),
        )
    })?;

    let mut key = Zeroizing([0u8; 32]);
    let bytes_to_copy = std::cmp::min(hash_bytes.as_bytes().len(), 32);
    key[..bytes_to_copy].copy_from_slice(&hash_bytes.as_bytes()[..bytes_to_copy]);
    Ok(key)
}

/// Creates a new single-key keystore protected by password.
pub fn create_keystore(path: &Path, password: &str) -> Result<(), CryptError> {
    // Generating random salt for argon2
    let mut salt_bytes = [0u8; 16];
    rand::fill(&mut salt_bytes);
    let salt_string = SaltString::encode_b64(&salt_bytes).map_err(|e| {
        CryptError::Argon2Error(
            "Error occurred while generating salt from B64 salt str".to_string(),
            e.to_string(),
        )
    })?;

    // Derive KEK from password
    let kek_bytes = derive_kek(password, salt_string.as_str())?;
    let kek = Key::<Aes256Gcm>::from(*kek_bytes);
    let cipher = Aes256Gcm::new(&kek);

    // Generate the Master Key that will be used to wrap/unwrap per-file DEKs
    let mut master_key_bytes = Zeroizing([0u8; 32]);
    rand::fill(&mut *master_key_bytes);

    // Encrypt the Master Key using the KEK
    let mut nonce_bytes = [0u8; 12]; // 96 bits for AES-GCM
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let encrypted_master_key = cipher
        .encrypt(&nonce, master_key_bytes.as_ref())
        .map_err(|e| {
            CryptError::AesGcmError(
                "Error occurred while encrypting Master Key".to_string(),
                e.to_string(),
            )
        })?;

    // Saving Keystore as a JSON file
    let keystore = KeyStore {
        version: CURRENT_KEYSTORE_VERSION,
        salt: salt_string.to_string(),
        nonce: STANDARD.encode(nonce),
        wrapped_key: STANDARD.encode(encrypted_master_key),
    };

    let json_data = serde_json::to_string_pretty(&keystore).map_err(|e| {
        CryptError::SerdeError(
            "Error serializing Keystore JSON data".to_string(),
            e.to_string(),
        )
    })?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                CryptError::Error("Error saving Keystore file".to_string(), e.to_string())
            })?;
        file.write_all(json_data.as_bytes()).map_err(|e| {
            CryptError::Error("Error saving Keystore file".to_string(), e.to_string())
        })?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, json_data).map_err(|e| {
            CryptError::Error("Error saving Keystore file".to_string(), e.to_string())
        })?;
    }

    Ok(())
}

pub fn load_keystore_key(path: &Path, password: &str) -> Result<Zeroizing<[u8; 32]>, CryptError> {
    let json_data = fs::read_to_string(path).map_err(|e| {
        CryptError::Error("Unable to load keystore file".to_string(), e.to_string())
    })?;
    let keystore = serde_json::from_str::<KeyStore>(&json_data).map_err(|e| {
        CryptError::SerdeError("Unable to deserialize Keystore".to_string(), e.to_string())
    })?;

    // Re-derive KEK from the user-provided password and saved salt
    let kek_bytes = derive_kek(password, &keystore.salt)?;
    let kek = Key::<Aes256Gcm>::from(*kek_bytes);
    let cipher = Aes256Gcm::new(&kek);

    // Decode nonce & wrapped key
    let nonce_bytes = STANDARD
        .decode(&keystore.nonce)
        .map_err(|e| CryptError::B64Error("Error decoding Nonce".to_string(), e.to_string()))?;
    let nonce = aes_gcm::Nonce::try_from(nonce_bytes.as_slice())
        .map_err(|e| CryptError::AesGcmError("Error decoding Nonce".to_string(), e.to_string()))?;
    let encrypted_master_key = STANDARD.decode(&keystore.wrapped_key).map_err(|e| {
        CryptError::B64Error("Error decoding Wrapped Key".to_string(), e.to_string())
    })?;

    // Decrypt to retrieve the actual master key
    let mut master_key_vec = cipher
        .decrypt(&nonce, encrypted_master_key.as_ref())
        .map_err(|e| {
            CryptError::AesGcmError(
                "Incorrect password or corrupted keystore".to_string(),
                e.to_string(),
            )
        })?;

    let master_key_bytes: [u8; 32] = master_key_vec.as_slice().try_into().map_err(|_| {
        CryptError::Error(
            "Decrypted master key is invalid length (expected 32 bytes)".to_string(),
            String::new(),
        )
    })?;
    master_key_vec.zeroize();

    Ok(Zeroizing(master_key_bytes))
}

/// Checks if provided master password is valid for a keystore or not.
pub fn verify_ks_master_password(ks_path: &Path, password: &str) -> Result<bool, CryptError> {
    match load_keystore_key(ks_path, password) {
        Ok(_) => Ok(true),
        // If decryption fails due to wrong password or any other AES-GCM related issues
        Err(CryptError::AesGcmError(_, _)) => Ok(false),
        // other errors
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_create_load_verify_roundtrip() {
        let temp_dir = std::env::temp_dir();
        let mut random_bytes = [0u8; 8];
        rand::fill(&mut random_bytes);
        let random_id: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let ks_path = temp_dir.join(format!("test_keystore_{random_id}.json"));

        let password = "TestMasterPassword123!";
        create_keystore(&ks_path, password).expect("Failed to create keystore");

        // Verify valid password
        let is_valid = verify_ks_master_password(&ks_path, password).expect("Verification failed");
        assert!(is_valid);

        // Verify invalid password
        let is_invalid = verify_ks_master_password(&ks_path, "WrongPassword!")
            .expect("Verification check failed");
        assert!(!is_invalid);

        // Load master key and check length
        let key = load_keystore_key(&ks_path, password).expect("Failed to load master key");
        assert_eq!(key.len(), 32);

        // Clean up
        let _ = fs::remove_file(&ks_path);
    }
}
