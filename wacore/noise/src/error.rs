use thiserror::Error;

/// Errors that can occur during Noise protocol operations.
#[derive(Debug, Clone, Error)]
pub enum NoiseError {
    #[error("Invalid pattern length: expected {expected}, got {got}")]
    InvalidPatternLength { expected: usize, got: usize },

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("AES-GCM encryption failed: {0}")]
    Encrypt(String),

    #[error("AES-GCM decryption failed: {0}")]
    Decrypt(String),

    #[error("ciphertext too short to contain authentication tag")]
    CiphertextTooShort,

    #[error("HKDF expansion failed")]
    HkdfExpandFailed,

    #[error("Invalid key length for {name}: expected {expected}, got {got}")]
    InvalidKeyLength {
        name: &'static str,
        expected: usize,
        got: usize,
    },

    #[error("Counter exhausted: nonce would be reused after 2^32 messages")]
    CounterExhausted,
}

pub type Result<T> = std::result::Result<T, NoiseError>;
