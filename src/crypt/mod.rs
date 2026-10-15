pub mod errors;
pub mod file_crypt;
pub mod keystore;

use std::{fs, path::PathBuf};

use anyhow::{Result, anyhow};
use rpassword::ConfigBuilder;

use crate::crypt::{file_crypt::decrypt_file_wks, keystore::create_keystore};

fn password_config() -> rpassword::Config {
    ConfigBuilder::new().password_feedback_mask('*').build()
}

pub fn prompt_password(prompt: &str) -> Result<String> {
    let config = password_config();
    Ok(rpassword::prompt_password_with_config(prompt, config)?)
}

pub fn encrypt_file_ks(keystore: &PathBuf, file: &PathBuf, output: &PathBuf) -> Result<()> {
    // checking keystore exists or not...
    if !keystore.exists() || keystore.is_dir() {
        println!(
            "Key Store doesn't exists in the given path...\n creating a new keystore in that path...."
        );

        let mut keystore_path = keystore.clone();
        if keystore.is_dir() {
            keystore_path = keystore_path.join("keystore.json");
        }

        let password = prompt_password("Enter New Master password: ")?;

        if let Err(e) = create_keystore(&keystore_path, &password) {
            eprintln!(" Error -> {}", e.to_string());
        }
        println!(" Generated Keystore ");
        return Ok(());
    }
    let password = prompt_password("Enter New Master password: ")?;
    let file_name = file
        .file_name()
        .ok_or_else(|| anyhow!("Invalid file name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Filename is not valid UTF-8"))?;
    let master_key = keystore::load_keystore_key(&keystore, &password)?;

    let raw_file_bytes = fs::read(&file)?;
    let ciphertext = file_crypt::encrypt_file_wks(&master_key, file_name, &raw_file_bytes)?;

    // Generate a random anonymous filename (e.g., "7f3b9a1c.enc") to prevent metadata leakage
    let mut random_bytes = [0u8; 8];
    rand::fill(&mut random_bytes);
    let random_id: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let output_filename = format!("{}.encrypted", random_id);
    let output_path = output.join(&output_filename);

    fs::write(&output_path, ciphertext)?;

    println!("    Successfully encrypted '{}'", file_name);
    println!(
        "   Saved anonymously as: '{}' (Server sees no metadata)",
        output_filename
    );

    return Ok(());
}

pub fn decyrpt_file_ks(keystore: &PathBuf, file: &PathBuf, output: &PathBuf) -> Result<()> {
    let password = prompt_password("Enter master password: ")?;
    let master_key = keystore::load_keystore_key(&keystore, &password)?;

    let ciphertext = fs::read(&file)?;
    let (original_filename, raw_file_data) = decrypt_file_wks(&master_key, &ciphertext)?;

    let mut output_path = output.clone();
    if output.is_dir() {
        output_path = output_path.join(&original_filename);
    }
    fs::write(&output_path, raw_file_data)?;

    println!(
        "   Successfully decrypted! Restored original file: '{}' \n saved at {}",
        original_filename,
        output_path.to_str().unwrap()
    );

    Ok(())
}

pub fn encyrpt_file_wp(file: &PathBuf, output: &PathBuf) -> Result<()> {
    if !file.exists() {
        eprintln!("File doesn't exists !!!!");
        return Ok(());
    }

    let file_name = file
        .file_name()
        .ok_or_else(|| anyhow!("Invalid file name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Filename is not valid UTF-8"))?;

    let password = prompt_password("Enter New Master password: ")?;
    let confirm = rpassword::prompt_password("Confirm encryption password: ")?;
    if password != confirm {
        eprintln!("❌ Error: Passwords do not match!");
        std::process::exit(1);
    }

    let raw_file_data = fs::read(&file)?;
    let ciphertext = file_crypt::encrypt_file_with_pwd(&password, file_name, &raw_file_data)?;

    // Generate a random anonymous filename (e.g., "7f3b9a1c.enc") to prevent metadata leakage
    let mut random_bytes = [0u8; 8];
    rand::fill(&mut random_bytes);
    let random_id: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let output_filename = format!("{}.encrypted", random_id);
    let output_path = output.join(&output_filename);

    fs::write(&output_path, ciphertext)?;

    println!("    Successfully encrypted '{}'", file_name);
    println!(
        "   Saved anonymously as: '{}' (Server sees no metadata)",
        output_filename
    );

    Ok(())
}

pub fn decyrpt_file_wp(file: &PathBuf, output: &PathBuf) -> Result<()> {
    if !file.exists() {
        eprintln!("File doesn't exists !!!!");
        return Ok(());
    }

    let password = rpassword::prompt_password("Enter decryption password: ")?;
    let ciphertext = fs::read(&file)?;

    let (original_filename, plaintext) = file_crypt::decrypt_file_with_pwd(&password, &ciphertext)?;

    let mut output_path = output.clone();
    if output.is_dir() {
        output_path = output_path.join(&original_filename);
    }
    fs::write(&output_path, plaintext)?;

    println!(
        "   Successfully decrypted! Restored original file: '{}' \n saved at {}",
        original_filename,
        output_path.to_str().unwrap()
    );

    Ok(())
}
