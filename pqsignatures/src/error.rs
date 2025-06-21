use thiserror::Error;

#[derive(Debug, Error)]
pub enum PQSignatureError {
    #[error("Invalid key length")] 
    InvalidKeyLength,
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Serialization error")]
    SerializationError,
    #[error("Unknown error")]
    Unknown,
}
