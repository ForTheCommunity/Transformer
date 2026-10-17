pub mod errors;
pub mod file_crypt;
pub mod keystore;

use std::{
    fs::{self, File},
    io::{BufReader, BufWriter},
    path::PathBuf,
};

use anyhow::{Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::ConfigBuilder;

use crate::crypt::keystore::create_keystore;

fn password_config() -> rpassword::Config {
    ConfigBuilder::new().password_feedback_mask('*').build()
}

pub fn prompt_password(prompt: &str) -> Result<String> {
    let config = password_config();
    Ok(rpassword::prompt_password_with_config(prompt, config)?)
}

// Create a styled progress bar for file operations.
fn make_progress_bar(total_bytes: u64, action: &str) -> ProgressBar {
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

pub fn encrypt_file_ks(
    keystore: &PathBuf,
    file: &PathBuf,
    output: &PathBuf,
    chunk_size: usize,
    password: Option<String>,
) -> Result<PathBuf> {
    let mut ks_master_password: Option<String> = None;
    if password.is_none() {
        ks_master_password = Some(prompt_password("Enter New Master password: ")?);
    } else if password.is_some() {
        ks_master_password = password
    }

    let file_name = file
        .file_name()
        .ok_or_else(|| anyhow!("Invalid file name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Filename is not valid UTF-8"))?;
    let master_key = keystore::load_keystore_key(&keystore, &ks_master_password.unwrap())?;

    // Generate a random anonymous filename (e.g., "7f3b9a1c.enc") to prevent metadata leakage
    let mut random_bytes = [0u8; 8];
    rand::fill(&mut random_bytes);
    let random_id: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let output_filename = format!("{}.encrypted", random_id);
    let tmp_filename = format!("{}.enc.tmp", random_id);
    let output_path = output.join(&output_filename);
    let tmp_path = output.join(&tmp_filename);

    let file_size = fs::metadata(file)?.len();
    let pb = make_progress_bar(file_size, "Encrypting");
    let mut reader = pb.wrap_read(BufReader::new(File::open(file)?));
    let mut writer = BufWriter::new(File::create(&tmp_path)?);

    file_crypt::encrypt_file_wks(&master_key, file_name, &mut reader, &mut writer, chunk_size)?;
    drop(writer); // flush before rename
    pb.finish_with_message("done");

    fs::rename(&tmp_path, &output_path)?;

    println!("    Successfully encrypted '{}'", file_name);
    println!(
        "   Saved anonymously as: '{}'",
        output_filename
    );

    Ok(output_path)
}

pub fn decyrpt_file_ks(keystore: &PathBuf, file: &PathBuf, output: &PathBuf) -> Result<()> {
    let password = prompt_password("Enter master password: ")?;
    let master_key = keystore::load_keystore_key(&keystore, &password)?;

    let file_size = fs::metadata(file)?.len();
    let pb = make_progress_bar(file_size, "Decrypting");
    let mut reader = pb.wrap_read(BufReader::new(File::open(file)?));

    // The original filename is only known after decryption. If `output` is a
    // directory we decrypt to a temp file first and then rename it.
    let (tmp_path, original_filename) = if output.is_dir() {
        let mut rng_bytes = [0u8; 8];
        rand::fill(&mut rng_bytes);
        let tmp_name: String = rng_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let tmp_path = output.join(format!("{}.dec.tmp", tmp_name));
        {
            let mut writer = BufWriter::new(File::create(&tmp_path)?);
            let name = file_crypt::decrypt_file_wks(&master_key, &mut reader, &mut writer)?;
            (tmp_path, name)
        }
    } else {
        let mut writer = BufWriter::new(File::create(output)?);
        let name = file_crypt::decrypt_file_wks(&master_key, &mut reader, &mut writer)?;
        (output.clone(), name)
    };
    pb.finish_with_message("done");

    let output_path = if output.is_dir() {
        let dest = output.join(&original_filename);
        fs::rename(&tmp_path, &dest)?;
        dest
    } else {
        tmp_path
    };

    println!(
        "   Successfully decrypted! Restored original file: '{}' \n saved at {}",
        original_filename,
        output_path.to_str().unwrap()
    );

    Ok(())
}

pub fn encyrpt_file_wp(
    file: &PathBuf,
    output: &PathBuf,
    password: &Option<String>,
    chunk_size: usize,
) -> Result<PathBuf> {
    if !file.exists() {
        eprintln!("File doesn't exists !!!!");
        return Err(anyhow!("File doesn't exists !!!!"));
    }

    let file_name = file
        .file_name()
        .ok_or_else(|| anyhow!("Invalid file name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Filename is not valid UTF-8"))?;

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

    // Generate a random anonymous filename (e.g., "7f3b9a1c.enc") to prevent metadata leakage
    let mut random_bytes = [0u8; 8];
    rand::fill(&mut random_bytes);
    let random_id: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let output_filename = format!("{}.encrypted", random_id);
    let tmp_filename = format!("{}.enc.tmp", random_id);
    let output_path = output.join(&output_filename);
    let tmp_path = output.join(&tmp_filename);

    let file_size = fs::metadata(file)?.len();
    let pb = make_progress_bar(file_size, "Encrypting");
    let mut reader = pb.wrap_read(BufReader::new(File::open(file)?));
    let mut writer = BufWriter::new(File::create(&tmp_path)?);

    file_crypt::encrypt_file_with_pwd(
        &final_password,
        file_name,
        &mut reader,
        &mut writer,
        chunk_size,
    )?;
    drop(writer); // flush before rename
    pb.finish_with_message("done");

    fs::rename(&tmp_path, &output_path)?;

    println!("    Successfully encrypted '{}'", file_name);
    println!(
        "   Saved anonymously as: '{}'",
        output_filename
    );

    Ok(output_path)
}

pub fn decyrpt_file_wp(file: &PathBuf, output: &PathBuf) -> Result<()> {
    if !file.exists() {
        eprintln!("File doesn't exists !!!!");
        return Ok(());
    }

    let password = rpassword::prompt_password("Enter decryption password: ")?;

    let file_size = fs::metadata(file)?.len();
    let pb = make_progress_bar(file_size, "Decrypting");
    let mut reader = pb.wrap_read(BufReader::new(File::open(file)?));

    // Same temp-file trick as in decyrpt_file_ks
    let (tmp_path, original_filename) = if output.is_dir() {
        let mut rng_bytes = [0u8; 8];
        rand::fill(&mut rng_bytes);
        let tmp_name: String = rng_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let tmp_path = output.join(format!("{}.dec.tmp", tmp_name));
        {
            let mut writer = BufWriter::new(File::create(&tmp_path)?);
            let name = file_crypt::decrypt_file_with_pwd(&password, &mut reader, &mut writer)?;
            (tmp_path, name)
        }
    } else {
        let mut writer = BufWriter::new(File::create(output)?);
        let name = file_crypt::decrypt_file_with_pwd(&password, &mut reader, &mut writer)?;
        (output.clone(), name)
    };
    pb.finish_with_message("done");

    let output_path = if output.is_dir() {
        let dest = output.join(&original_filename);
        fs::rename(&tmp_path, &dest)?;
        dest
    } else {
        tmp_path
    };

    println!(
        "   Successfully decrypted! Restored original file: '{}' \n saved at {}",
        original_filename,
        output_path.to_str().unwrap()
    );

    Ok(())
}
