use std::fmt;

#[derive(Debug, Clone)]
pub enum RndcError {
    InvalidAlgorithm(String),
    Base64DecodeError(String),
    NetworkError(String),
    EncodingError(String),
    DecodingError(String),
    UnknownError(String),
}
impl fmt::Display for RndcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RndcError::InvalidAlgorithm(msg) => write!(f, "Invalid algorithm: {}", msg),
            RndcError::Base64DecodeError(msg) => write!(f, "Base64 decode error: {}", msg),
            RndcError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            RndcError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
            RndcError::DecodingError(msg) => write!(f, "Decoding error: {}", msg),
            RndcError::UnknownError(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

impl std::error::Error for RndcError {}
