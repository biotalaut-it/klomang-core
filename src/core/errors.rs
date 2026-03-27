use std::fmt;

/// Core engine errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    BlockNotFound,
    InvalidParent,
    DuplicateBlock,
    ConsensusError,
    TransactionError(String),
    InvalidSignature,
    InvalidPublicKey,
    SignatureVerificationFailed,
    ConfigError(String),
    SerializationError(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CoreError::BlockNotFound => write!(f, "Block not found"),
            CoreError::InvalidParent => write!(f, "Invalid parent"),
            CoreError::DuplicateBlock => write!(f, "Duplicate block"),
            CoreError::ConsensusError => write!(f, "Consensus error"),
            CoreError::TransactionError(msg) => write!(f, "Transaction error: {}", msg),
            CoreError::InvalidSignature => write!(f, "Invalid signature"),
            CoreError::InvalidPublicKey => write!(f, "Invalid public key"),
            CoreError::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            CoreError::ConfigError(msg) => write!(f, "Config error: {}", msg),
            CoreError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for CoreError {}