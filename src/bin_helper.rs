use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::ConfigBuilder;
use transformer::{
    crypt::{
        decrypt_file_ks, decrypt_file_wp, encrypt_file_ks, encrypt_file_wp,
        keystore::create_keystore, zeroize::Zeroize,
    },
    parse_to_bytes,
    preety_print,
    split_merge::{
        MergeProgress, SplitProgress, calculate_split_layout, inspect_piece, merge_pieces,
        split_file,
    },
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

/// CLI wrapper with progress reporting.
pub fn split_bin_helper(file_path: &Path, piece_size_str: &str, output_dir: &Path) -> Result<()> {
    let piece_size = parse_to_bytes(piece_size_str)?;
    let metadata = fs::metadata(file_path)?;
    if metadata.is_dir() {
        return Err(anyhow!("Expected a file path, not a directory"));
    }
    let file_size = metadata.len();
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("Invalid filename: unable to extract valid UTF-8 filename"))?;
    let (header_len, payload_per_piece, total_pieces) =
        calculate_split_layout(file_name, file_size, piece_size)?;

    preety_print!("File Size in Bytes", file_size);
    preety_print!("Max Piece Size in Bytes", piece_size);
    preety_print!("Piece Header Size", header_len);
    preety_print!("Payload Bytes per Piece", payload_per_piece);
    preety_print!("Total Estimated Pieces", total_pieces);

    let hash_pb = make_progress_bar(file_size, "Hashing  ");
    let mut split_pb: Option<ProgressBar> = None;

    let res = split_file(file_path, piece_size, output_dir, |progress| match progress {
        SplitProgress::Hashing { bytes_read, .. } => {
            hash_pb.inc(bytes_read);
        }
        SplitProgress::Splitting { bytes_written, .. } => {
            let pb = split_pb.get_or_insert_with(|| {
                hash_pb.finish_and_clear();
                make_progress_bar(file_size, "Splitting")
            });
            pb.inc(bytes_written);
        }
    })?;

    hash_pb.finish_and_clear();
    if let Some(pb) = split_pb {
        pb.finish_and_clear();
    }

    let hash_hex: String = res.original_file_hash.iter().map(|b| format!("{:02x}", b)).collect();
    println!(
        "   ✓  Split '{}' into {} pieces (BLAKE3: {})",
        res.original_filename, res.total_pieces, hash_hex
    );

    Ok(())
}

/// CLI wrapper with progress reporting.
pub fn merge_bin_helper(piece_path: &Path, output_dir: &Path) -> Result<()> {
    let header = inspect_piece(piece_path)?;
    preety_print!("Original File", header.original_filename);
    preety_print!("Total Pieces", header.total_pieces);

    let pb = make_progress_bar(header.original_file_size, "Merging  ");
    let pb_clone = pb.clone();

    let res = merge_pieces(piece_path, output_dir, move |progress| match progress {
        MergeProgress::Merging { bytes_written, .. } => {
            pb_clone.inc(bytes_written);
        }
    })?;

    pb.finish_and_clear();

    let hash_hex: String = res.file_hash.iter().map(|b| format!("{:02x}", b)).collect();
    println!(
        "   ✓  Merged {} pieces -> '{}' (BLAKE3 verified: {})",
        res.total_pieces,
        res.output_path.display(),
        hash_hex
    );

    Ok(())
}
