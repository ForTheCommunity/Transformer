pub mod errors;
pub mod file_crypt;
pub mod keystore;
pub mod zeroize;

use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read},
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};

use crate::crypt::{
    keystore::verify_ks_master_password,
    zeroize::Zeroize,
};

/// RAII Guard that ensures temporary files are deleted if an operation does not complete successfully.
pub(crate) struct TempFileGuard {
    path: PathBuf,
    active: bool,
}

impl TempFileGuard {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path, active: true }
    }

    pub(crate) fn disarm(&mut self) {
        self.active = false;
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

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
    keystore: &Path,
    file: &Path,
    output: &Path,
    chunk_size: usize,
    mut ks_master_password: String,
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
    let master_key = keystore::load_keystore_key(keystore, &ks_master_password)?;
    ks_master_password.zeroize();

    // Generate a random anonymous filename (e.g., "7f3b9a1c.encrypted") to prevent metadata leakage
    let mut random_bytes = [0u8; 8];
    rand::fill(&mut random_bytes);
    let random_id: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let output_filename = format!("{}.encrypted", random_id);
    let tmp_filename = format!("{}.enc.tmp", random_id);
    let output_path = output.join(&output_filename);
    let tmp_path = output.join(&tmp_filename);

    let mut guard = TempFileGuard::new(tmp_path);

    let file_handle = File::open(file)?;
    let mut reader = CallbackReader {
        inner: BufReader::new(file_handle),
        callback: &mut on_progress,
    };

    let mut writer = BufWriter::new(File::create(guard.path())?);

    file_crypt::encrypt_file_wks(&master_key, file_name, &mut reader, &mut writer, chunk_size)?;
    drop(writer); // flush before rename

    fs::rename(guard.path(), &output_path)?;
    guard.disarm();

    if delete {
        fs::remove_file(file)?;
    }

    Ok(output_path)
}

pub fn decrypt_file_ks<F>(
    keystore: &Path,
    file: &Path,
    output: &Path,
    mut ks_master_password: String,
    delete: bool,
    mut on_progress: F,
) -> Result<PathBuf>
where
    F: FnMut(u64),
{
    let master_key = keystore::load_keystore_key(keystore, &ks_master_password)?;
    ks_master_password.zeroize();

    let file_handle = File::open(file)?;
    let mut reader = CallbackReader {
        inner: BufReader::new(file_handle),
        callback: &mut on_progress,
    };

    let mut rng_bytes = [0u8; 8];
    rand::fill(&mut rng_bytes);
    let tmp_name: String = rng_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    // The original filename is only known after decryption. We always decrypt to a
    // temporary file first to guarantee atomic writes and avoid leaving corrupted files on failure.
    let tmp_path = if output.is_dir() {
        output.join(format!("{}.dec.tmp", tmp_name))
    } else {
        let parent = output.parent().unwrap_or_else(|| Path::new("."));
        parent.join(format!("{}.dec.tmp", tmp_name))
    };

    let mut guard = TempFileGuard::new(tmp_path);

    let original_filename = {
        let mut writer = BufWriter::new(File::create(guard.path())?);
        file_crypt::decrypt_file_wks(&master_key, &mut reader, &mut writer)?
    };

    let output_path = if output.is_dir() {
        let dest = output.join(&original_filename);
        fs::rename(guard.path(), &dest)?;
        dest
    } else {
        fs::rename(guard.path(), output)?;
        output.to_path_buf()
    };
    guard.disarm();

    if delete {
        fs::remove_file(file)?;
    }

    Ok(output_path)
}

pub fn encrypt_file_wp<F>(
    file: &Path,
    output: &Path,
    mut password: String,
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

    // Generate a random anonymous filename (e.g., "7f3b9a1c.encrypted") to prevent metadata leakage
    let mut random_bytes = [0u8; 8];
    rand::fill(&mut random_bytes);
    let random_id: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let output_filename = format!("{}.encrypted", random_id);
    let tmp_filename = format!("{}.enc.tmp", random_id);
    let output_path = output.join(&output_filename);
    let tmp_path = output.join(&tmp_filename);

    let mut guard = TempFileGuard::new(tmp_path);

    let file_handle = File::open(file)?;
    let mut reader = CallbackReader {
        inner: BufReader::new(file_handle),
        callback: &mut on_progress,
    };

    let mut writer = BufWriter::new(File::create(guard.path())?);

    file_crypt::encrypt_file_with_pwd(&password, file_name, &mut reader, &mut writer, chunk_size)?;
    password.zeroize();
    drop(writer); // flush before rename

    fs::rename(guard.path(), &output_path)?;
    guard.disarm();

    if delete {
        fs::remove_file(file)?;
    }

    Ok(output_path)
}

pub fn decrypt_file_wp<F>(
    file: &Path,
    output: &Path,
    mut password: String,
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

    let mut rng_bytes = [0u8; 8];
    rand::fill(&mut rng_bytes);
    let tmp_name: String = rng_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    let tmp_path = if output.is_dir() {
        output.join(format!("{}.dec.tmp", tmp_name))
    } else {
        let parent = output.parent().unwrap_or_else(|| Path::new("."));
        parent.join(format!("{}.dec.tmp", tmp_name))
    };

    let mut guard = TempFileGuard::new(tmp_path);

    let original_filename = {
        let mut writer = BufWriter::new(File::create(guard.path())?);
        file_crypt::decrypt_file_with_pwd(&password, &mut reader, &mut writer)?
    };
    password.zeroize();

    let output_path = if output.is_dir() {
        let dest = output.join(&original_filename);
        fs::rename(guard.path(), &dest)?;
        dest
    } else {
        fs::rename(guard.path(), output)?;
        output.to_path_buf()
    };
    guard.disarm();

    if delete {
        fs::remove_file(file)?;
    }

    Ok(output_path)
}

// ─── Deprecated Compatibility Aliases ────────────────────────────────────────

#[deprecated(note = "Use decrypt_file_ks instead")]
pub fn decyrpt_file_ks<F>(
    keystore: &Path,
    file: &Path,
    output: &Path,
    ks_master_password: String,
    delete: bool,
    on_progress: F,
) -> Result<PathBuf>
where
    F: FnMut(u64),
{
    decrypt_file_ks(keystore, file, output, ks_master_password, delete, on_progress)
}

#[deprecated(note = "Use encrypt_file_wp instead")]
pub fn encyrpt_file_wp<F>(
    file: &Path,
    output: &Path,
    password: String,
    chunk_size: usize,
    delete: bool,
    on_progress: F,
) -> Result<PathBuf>
where
    F: FnMut(u64),
{
    encrypt_file_wp(file, output, password, chunk_size, delete, on_progress)
}

#[deprecated(note = "Use decrypt_file_wp instead")]
pub fn decyrpt_file_wp<F>(
    file: &Path,
    output: &Path,
    password: String,
    delete: bool,
    on_progress: F,
) -> Result<PathBuf>
where
    F: FnMut(u64),
{
    decrypt_file_wp(file, output, password, delete, on_progress)
}

/// Verifies provided Master Password against provided Keystore.
pub fn check_master_password(path: &Path, password: &str) -> Result<bool, String> {
    match verify_ks_master_password(path, password) {
        Ok(result) => Ok(result),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_file_encrypt_decrypt_wp_roundtrip() {
        let temp_dir = std::env::temp_dir();
        let mut rng = [0u8; 8];
        rand::fill(&mut rng);
        let id: String = rng.iter().map(|b| format!("{:02x}", b)).collect();

        let src_file = temp_dir.join(format!("test_src_{id}.txt"));
        let mut f = File::create(&src_file).unwrap();
        f.write_all(b"Hello world from automated integration test!").unwrap();
        drop(f);

        let password = "TestPassword_12345".to_string();
        let enc_path = encrypt_file_wp(&src_file, &temp_dir, password.clone(), 64, false, |_| {})
            .expect("encrypt failed");

        let dec_path = decrypt_file_wp(&enc_path, &temp_dir, password, false, |_| {})
            .expect("decrypt failed");

        assert_eq!(dec_path, src_file);
        let decrypted_content = fs::read(&dec_path).unwrap();
        assert_eq!(decrypted_content, b"Hello world from automated integration test!");

        // Cleanup
        let _ = fs::remove_file(&src_file);
        let _ = fs::remove_file(&enc_path);
    }

    #[test]
    fn test_file_encrypt_decrypt_ks_roundtrip() {
        let temp_dir = std::env::temp_dir();
        let mut rng = [0u8; 8];
        rand::fill(&mut rng);
        let id: String = rng.iter().map(|b| format!("{:02x}", b)).collect();

        let ks_file = temp_dir.join(format!("test_ks_{id}.json"));
        let master_pwd = "MasterPassword_12345".to_string();
        keystore::create_keystore(&ks_file, &master_pwd).unwrap();

        let src_file = temp_dir.join(format!("test_ks_src_{id}.txt"));
        let mut f = File::create(&src_file).unwrap();
        f.write_all(b"Confidential keystore encrypted payload").unwrap();
        drop(f);

        let enc_path = encrypt_file_ks(&ks_file, &src_file, &temp_dir, 64, master_pwd.clone(), false, |_| {})
            .expect("keystore encrypt failed");

        let dec_path = decrypt_file_ks(&ks_file, &enc_path, &temp_dir, master_pwd, false, |_| {})
            .expect("keystore decrypt failed");

        // Verify correct path without double-joining filename
        assert_eq!(dec_path, src_file);
        assert!(dec_path.exists());

        let decrypted_content = fs::read(&dec_path).unwrap();
        assert_eq!(decrypted_content, b"Confidential keystore encrypted payload");

        // Cleanup
        let _ = fs::remove_file(&ks_file);
        let _ = fs::remove_file(&src_file);
        let _ = fs::remove_file(&enc_path);
    }
}
