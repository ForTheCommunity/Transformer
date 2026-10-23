use std::{fs, path::PathBuf};

use anyhow::{Ok, Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::ConfigBuilder;
use transformer::crypt::{
    decyrpt_file_ks, decyrpt_file_wp, encrypt_file_ks, encyrpt_file_wp, keystore::create_keystore,
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
                "  {{spinner:.cyan}} {action} [{{bar:40.cyan/dim}}] {{bytes}}/{{total_bytes}} ({{eta}})"
            ))
            .expect("invalid progress bar template")
            .progress_chars("━╸─"),
    );
    pb
}

pub fn create_ks(path: &PathBuf) -> Result<()> {
    let mut keystore_path = PathBuf::new();
    if path.is_dir() {
        keystore_path = path.join("keystore.json")
    }

    let password = prompt_password("    Enter New Master password: ")?;
    let confirm_password = prompt_password("    Confirm Password: ")?;

    if password != confirm_password {
        return Err(anyhow!(" Password didn't matched !!!"));
    }

    if let Err(e) = create_keystore(&keystore_path, &password) {
        eprintln!(" Error -> {}", e.to_string());
    }
    println!(" Generated Keystore at {}", keystore_path.to_str().unwrap());
    return Ok(());
}

// encrypt file with keystore bin helper.
pub fn efwks_bin_helper(
    keystore: &PathBuf,
    file: &PathBuf,
    output: &PathBuf,
    chunk_size: usize,
    password: Option<String>,
) -> Result<PathBuf> {
    let mut ks_master_password = String::new();
    if password.is_none() {
        ks_master_password = prompt_password("Enter Your Master password: ")?;
    } else if password.is_some() {
        ks_master_password = password.unwrap()
    }

    // proggress bar
    let file_size = fs::metadata(&file)?.len();
    let pb = make_progress_bar(file_size, "Encrypting");
    let pb_clone = pb.clone();

    let keystore_path = keystore.clone();
    let file_path = file.clone();
    let output_path = output.clone();
    let encrypted_file_path = encrypt_file_ks(
        &keystore_path,
        &file_path,
        &output_path,
        chunk_size,
        ks_master_password,
        move |bytes_read| {
            // This closure fires on every chunk read, updating the progress bar smoothly
            pb_clone.inc(bytes_read);
        },
    )?;

    pb.finish_with_message("done");

    Ok(encrypted_file_path)
}

// decrypt file with keystore bin helper.
pub fn dfwks_bin_helper(
    keystore: &PathBuf,
    file: &PathBuf,
    output: &PathBuf,
    password: &Option<String>,
) -> Result<PathBuf> {
    let master_password = match password {
        Some(pwd) => pwd.to_string(),
        None => prompt_password("    Enter master password: ")?,
    };

    let file_size = fs::metadata(&file)?.len();
    let pb = make_progress_bar(file_size, "Decrypting");
    let pb_clone = pb.clone();

    let result = decyrpt_file_ks(
        &keystore,
        &file,
        &output,
        master_password,
        move |bytes_read| {
            pb_clone.inc(bytes_read);
        },
    )?;

    let msg = format!(
        "   Successfully decrypted! Restored original file: '{}' from {}",
        result.file_name().unwrap().to_str().unwrap(),
        file.file_name().unwrap().to_str().unwrap(),
    );

    pb.finish_with_message(msg);

    Ok(result)
}

// encrypt file with password bin helper.
pub fn efwkp_bin_helper(
    file: &PathBuf,
    output: &PathBuf,
    password: &Option<String>,
    chunk_size: usize,
) -> Result<()> {
    if !file.exists() {
        return Err(anyhow!("File doesn't exists !!!!"));
    }

    let final_password = match password {
        Some(password) => password.to_owned(),
        None => {
            let input_pwd = prompt_password("Enter New Master password: ")?;
            let confirm_pwd = rpassword::prompt_password("Confirm encryption password: ")?;
            if input_pwd != confirm_pwd {
                eprintln!("❌ Error: Passwords do not match!");
                std::process::exit(1);
            }
            input_pwd
        }
    };

    let file_size = fs::metadata(&file)?.len();
    let pb = make_progress_bar(file_size, "Encrypting");
    let pb_clone = pb.clone();

    let output = encyrpt_file_wp(
        file,
        output,
        final_password,
        chunk_size,
        move |bytes_read| {
            pb_clone.inc(bytes_read);
        },
    )?;

    let msg = format!(
        "Encrypted file {} -> {}",
        file.file_name().unwrap().to_str().unwrap(),
        output.file_name().unwrap().to_str().unwrap()
    );

    pb.finish_with_message(msg);

    Ok(())
}

// decrypt file with password bin helper.
pub fn dfwkp_bin_helper(file: &PathBuf, output: &PathBuf, password: &Option<String>) -> Result<()> {
    if !file.exists() {
        return Err(anyhow!("File doesn't exists !!!!"));
    }

    let final_password = match password {
        Some(pwd) => pwd.to_owned(),
        None => rpassword::prompt_password("Enter decryption password: ")?,
    };

    let file_size = fs::metadata(&file)?.len();
    let pb = make_progress_bar(file_size, "Decrypting");
    let pb_clone = pb.clone();

    let output = decyrpt_file_wp(file, output, final_password, move |bytes_read| {
        pb_clone.inc(bytes_read);
    })?;

    let msg = format!(
        "Decrypted: {}, Restored orignal file: {}",
        file.file_name().unwrap().to_str().unwrap(),
        output.file_name().unwrap().to_str().unwrap()
    );
    pb.finish_with_message(msg);

    Ok(())
}
