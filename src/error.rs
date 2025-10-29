use thiserror::Error;

#[derive(Error, Debug)]
pub enum PqcError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    
    #[error("Encryption failed: {0}")]
    Encryption(String),
    
    #[error("Decryption failed: {0}")]
    Decryption(String),
    
    #[error("Signature generation failed: {0}")]
    Signing(String),
    
    #[error("Signature verification failed: {0}")]
    Verification(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("I/O error: {0}")]
    Io(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

pub type Result<T> = std::result::Result<T, PqcError>;