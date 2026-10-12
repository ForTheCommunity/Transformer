use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptError {
    #[error("{0}, Error -> {1}")]
    Error(String, std::io::Error),

    #[error("B64 Error: {0}, Error -> {1}")]
    B64Error(String, String),

    #[error("Serde Error: {0}, Error -> {1}")]
    SerdeError(String, String),

    #[error("Error: {0}, Argon2 Error -> {1}")]
    Argon2Error(String, String),

    #[error("Error: {0}, AesGcm Error -> {1}")]
    AesGcmError(String, String),
}
