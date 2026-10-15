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

pub fn encrypt_file_ks(
    keystore: &PathBuf,
    file: &PathBuf,
    output: &PathBuf,
    chunk_size: usize,
) -> Result<()> {
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
        "   Saved anonymously as: '{}' (Server sees no metadata)",
        output_filename
    );

    return Ok(());
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

pub fn encyrpt_file_wp(file: &PathBuf, output: &PathBuf, chunk_size: usize) -> Result<()> {
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

    file_crypt::encrypt_file_with_pwd(&password, file_name, &mut reader, &mut writer, chunk_size)?;
    drop(writer); // flush before rename
    pb.finish_with_message("done");

    fs::rename(&tmp_path, &output_path)?;

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
