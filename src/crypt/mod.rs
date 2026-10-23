pub mod errors;
pub mod file_crypt;
pub mod keystore;

use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read},
    path::PathBuf,
};

use anyhow::{Result, anyhow};

use crate::crypt::keystore::verify_ks_master_password;

struct CallbackReader<R, F> {
    inner: R,
    callback: F,
}

impl<R: Read, F: FnMut(u64)> Read for CallbackReader<R, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            (self.callback)(n as u64);
        }
        Ok(n)
    }
}

pub fn encrypt_file_ks<F>(
    keystore: &PathBuf,
    file: &PathBuf,
    output: &PathBuf,
    chunk_size: usize,
    ks_master_password: String,
    delete: bool,
    mut on_progress: F, // Progress Callback
) -> Result<PathBuf>
where
    F: FnMut(u64),
{
    let file_name = file
        .file_name()
        .ok_or_else(|| anyhow!("Invalid file name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Filename is not valid UTF-8"))?;
    let master_key = keystore::load_keystore_key(&keystore, &ks_master_password)?;

    // Generate a random anonymous filename (e.g., "7f3b9a1c.enc") to prevent metadata leakage
    let mut random_bytes = [0u8; 8];
    rand::fill(&mut random_bytes);
    let random_id: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let output_filename = format!("{}.encrypted", random_id);
    let tmp_filename = format!("{}.enc.tmp", random_id);
    let output_path = output.join(&output_filename);
    let tmp_path = output.join(&tmp_filename);

    let file_handle = File::open(file)?;
    let mut reader = CallbackReader {
        inner: BufReader::new(file_handle),
        callback: &mut on_progress,
    };

    let mut writer = BufWriter::new(File::create(&tmp_path)?);

    file_crypt::encrypt_file_wks(&master_key, file_name, &mut reader, &mut writer, chunk_size)?;
    drop(writer); // flush before rename

    if delete {
        fs::rename(&tmp_path, &output_path)?;
    }

    Ok(output_path)
}

pub fn decyrpt_file_ks<F>(
    keystore: &PathBuf,
    file: &PathBuf,
    output: &PathBuf,
    ks_master_password: String,
    delete: bool,
    mut on_progress: F,
) -> Result<PathBuf>
where
    F: FnMut(u64),
{
    let master_key = keystore::load_keystore_key(&keystore, &ks_master_password)?;

    let file_handle = File::open(file)?;
    let mut reader = CallbackReader {
        inner: BufReader::new(file_handle),
        callback: &mut on_progress,
    };

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

    let output_path = if output.is_dir() {
        let dest = output.join(&original_filename);
        fs::rename(&tmp_path, &dest)?;
        dest
    } else {
        tmp_path
    };

    if delete {
        fs::remove_file(file)?;
    }

    Ok(PathBuf::from(output_path.to_str().unwrap()).join(original_filename))
}

pub fn encyrpt_file_wp<F>(
    file: &PathBuf,
    output: &PathBuf,
    password: String,
    chunk_size: usize,
    delete: bool,
    mut on_progress: F,
) -> Result<PathBuf>
where
    F: FnMut(u64),
{
    let file_name = file
        .file_name()
        .ok_or_else(|| anyhow!("Invalid file name"))?
        .to_str()
        .ok_or_else(|| anyhow!("Filename is not valid UTF-8"))?;

    // Generate a random anonymous filename (e.g., "7f3b9a1c.enc") to prevent metadata leakage
    let mut random_bytes = [0u8; 8];
    rand::fill(&mut random_bytes);
    let random_id: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let output_filename = format!("{}.encrypted", random_id);
    let tmp_filename = format!("{}.enc.tmp", random_id);
    let output_path = output.join(&output_filename);
    let tmp_path = output.join(&tmp_filename);

    let file_handle = File::open(file)?;
    let mut reader = CallbackReader {
        inner: BufReader::new(file_handle),
        callback: &mut on_progress,
    };

    let mut writer = BufWriter::new(File::create(&tmp_path)?);

    file_crypt::encrypt_file_with_pwd(&password, file_name, &mut reader, &mut writer, chunk_size)?;
    drop(writer); // flush before rename

    fs::rename(&tmp_path, &output_path)?;

    if delete {
        fs::remove_file(file)?;
    }

    Ok(output_path)
}

pub fn decyrpt_file_wp<F>(
    file: &PathBuf,
    output: &PathBuf,
    password: String,
    delete: bool,
    mut on_progress: F,
) -> Result<PathBuf>
where
    F: FnMut(u64),
{
    let file_handle = File::open(file)?;
    let mut reader = CallbackReader {
        inner: BufReader::new(file_handle),
        callback: &mut on_progress,
    };

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

    let output_path = if output.is_dir() {
        let dest = output.join(&original_filename);
        fs::rename(&tmp_path, &dest)?;
        dest
    } else {
        tmp_path
    };

    if delete {
        fs::remove_file(file)?;
    }

    Ok(output_path)
}

/// Verifies provided Master Password against provided Keystore.
pub fn check_master_password(path: &PathBuf, password: &str) -> Result<bool, String> {
    match verify_ks_master_password(path, password) {
        Ok(result) => Ok(result),
        Err(e) => Err(e.to_string()),
    }
}
