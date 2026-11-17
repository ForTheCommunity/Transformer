use std::{
    fs,
    path::{Path, PathBuf},
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

/// Sanitizes an embedded filename to extract only a safe leaf filename component,
/// preventing path traversal (`..`, `/`, `\`, drive prefixes).
pub(crate) fn sanitize_filename(raw_name: &str) -> Option<String> {
    let base_name = Path::new(raw_name)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")?;
    Some(base_name.to_string())
}

/// Generates an 8-byte (16 hex char) random identifier for temporary/anonymous filenames.
pub(crate) fn random_hex_id() -> String {
    let mut bytes = [0u8; 8];
    rand::fill(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
