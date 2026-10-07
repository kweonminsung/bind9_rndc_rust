use std::fmt;

#[derive(Debug, Clone)]
pub enum RndcError {
    InvalidAlgorithm(String),
    Base64DecodeError(String),
    NetworkError(String),
    /// The configured command timeout is zero or too large.
    InvalidTimeout(String),
    /// The connection or command exceeded its time limit.
    TimeoutError(String),
    EncodingError(String),
    DecodingError(String),
    /// The server response has missing, malformed, or invalid auth data.
    AuthError(String),
}
impl fmt::Display for RndcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RndcError::InvalidAlgorithm(msg) => write!(f, "Invalid algorithm: {}", msg),
            RndcError::Base64DecodeError(msg) => write!(f, "Base64 decode error: {}", msg),
            RndcError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            RndcError::InvalidTimeout(msg) => write!(f, "Invalid timeout: {}", msg),
            RndcError::TimeoutError(msg) => write!(f, "Timeout error: {}", msg),
            RndcError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
            RndcError::DecodingError(msg) => write!(f, "Decoding error: {}", msg),
            RndcError::AuthError(msg) => write!(f, "Auth error: {}", msg),
        }
    }
}

impl std::error::Error for RndcError {}
