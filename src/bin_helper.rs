use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::ConfigBuilder;
use transformer::crypt::{
    decrypt_file_ks, decrypt_file_wp, encrypt_file_ks, encrypt_file_wp, keystore::create_keystore,
    zeroize::Zeroize,
};

fn password_config() -> rpassword::Config {
    ConfigBuilder::new().password_feedback_mask('*').build()
}

pub fn prompt_password(prompt: &str) -> Result<String> {
    let config = password_config();
    Ok(rpassword::prompt_password_with_config(prompt, config)?)
}

// Create a styled progress bar for file operations.
pub fn make_progress_bar(total_bytes: u64, action: &str) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(&format!(
                "  {{spinner:.cyan}} {action} [{{bar:40.cyan/dim}}] {{bytes}}/{{total_bytes}} (ETA: {{eta}})"
            ))
            .expect("invalid progress bar template")
            .progress_chars("━╸─"),
    );
    pb
}

pub fn create_ks(path: &Path) -> Result<()> {
    let mut keystore_path = PathBuf::new();
    if path.is_dir() {
        keystore_path = path.join("keystore.json")
    }

    let mut password = prompt_password("    Enter New Master password: ")?;
    let mut confirm_password = prompt_password("    Confirm Password: ")?;

    if password != confirm_password {
        password.zeroize();
        confirm_password.zeroize();
        return Err(anyhow!(" Password didn't match !!!"));
    }
    confirm_password.zeroize();

    if let Err(e) = create_keystore(&keystore_path, &password) {
        eprintln!(" Error -> {e}");
    }
    password.zeroize();
    println!(" Generated Keystore at {}", keystore_path.to_str().unwrap());
    Ok(())
}

// Encrypt file with keystore bin helper.
pub fn efwks_bin_helper(
    keystore: &Path,
    file: &Path,
    output: &Path,
    chunk_size: usize,
    password: Option<String>,
    delete: bool,
) -> Result<PathBuf> {
    let ks_master_password = match password {
        Some(pwd) => pwd,
        None => prompt_password("    Enter Your Master password: ")?,
    };

    let file_size = fs::metadata(file)?.len();
    let pb = make_progress_bar(file_size, "Encrypting");
    let pb_clone = pb.clone();

    let encrypted_file_path = encrypt_file_ks(
        keystore,
        file,
        output,
        chunk_size,
        ks_master_password,
        delete,
        move |bytes_read| {
            pb_clone.inc(bytes_read);
        },
    )?;

    pb.finish_and_clear();

    let msg = format!(
        "   ✓  Encrypted File {} -> {}",
        encrypted_file_path.file_name().unwrap().to_str().unwrap(),
        file.file_name().unwrap().to_str().unwrap(),
    );

    println!("{msg}");

    Ok(encrypted_file_path)
}

// Decrypt file with keystore bin helper.
pub fn dfwks_bin_helper(
    keystore: &Path,
    file: &Path,
    output: &Path,
    password: &Option<String>,
    delete: bool,
) -> Result<PathBuf> {
    let master_password = match password {
        Some(pwd) => pwd.to_string(),
        None => prompt_password("    Enter master password: ")?,
    };

    let file_size = fs::metadata(file)?.len();
    let pb = make_progress_bar(file_size, "Decrypting");
    let pb_clone = pb.clone();

    let result = decrypt_file_ks(
        keystore,
        file,
        output,
        master_password,
        delete,
        move |bytes_read| {
            pb_clone.inc(bytes_read);
        },
    )?;

    pb.finish_and_clear();

    let msg = format!(
        "   ✓  Successfully decrypted! Restored original file: '{}' from {}",
        result.file_name().unwrap().to_str().unwrap(),
        file.file_name().unwrap().to_str().unwrap(),
    );

    println!("{msg}");

    Ok(result)
}

// Encrypt file with password bin helper.
pub fn efwkp_bin_helper(
    file: &Path,
    output: &Path,
    password: &Option<String>,
    chunk_size: usize,
    delete: bool,
) -> Result<()> {
    if !file.exists() {
        return Err(anyhow!("File doesn't exist !!!!"));
    }

    let final_password = match password {
        Some(pwd) => pwd.to_owned(),
        None => {
            let mut input_pwd = prompt_password("Enter a password to encrypt file: ")?;
            let mut confirm_pwd = prompt_password("Confirm encryption password: ")?;
            if input_pwd != confirm_pwd {
                input_pwd.zeroize();
                confirm_pwd.zeroize();
                eprintln!("   ❌ Error: Passwords do not match!");
                std::process::exit(1);
            }
            confirm_pwd.zeroize();
            input_pwd
        }
    };

    let file_size = fs::metadata(file)?.len();
    let pb = make_progress_bar(file_size, "Encrypting");
    let pb_clone = pb.clone();

    let output_res = encrypt_file_wp(
        file,
        output,
        final_password,
        chunk_size,
        delete,
        move |bytes_read| {
            pb_clone.inc(bytes_read);
        },
    )?;

    pb.finish_and_clear();

    let msg = format!(
        "   ✓  Encrypted file {} -> {}",
        file.file_name().unwrap().to_str().unwrap(),
        output_res.file_name().unwrap().to_str().unwrap()
    );

    println!("{msg}");

    Ok(())
}

// Decrypt file with password bin helper.
pub fn dfwkp_bin_helper(
    file: &Path,
    output: &Path,
    password: &Option<String>,
    delete: bool,
) -> Result<()> {
    if !file.exists() {
        return Err(anyhow!("File doesn't exist !!!!"));
    }

    let final_password = match password {
        Some(pwd) => pwd.to_owned(),
        None => rpassword::prompt_password("Enter decryption password: ")?,
    };

    let file_size = fs::metadata(file)?.len();
    let pb = make_progress_bar(file_size, "Decrypting");
    let pb_clone = pb.clone();

    let output_res = decrypt_file_wp(file, output, final_password, delete, move |bytes_read| {
        pb_clone.inc(bytes_read);
    })?;

    pb.finish_and_clear();

    let msg = format!(
        "   ✓ Decrypted: {}, Restored original file: {}",
        file.file_name().unwrap().to_str().unwrap(),
        output_res.file_name().unwrap().to_str().unwrap()
    );

    println!("{msg}");

    Ok(())
}
