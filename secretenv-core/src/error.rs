use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("file too short to be a valid .env.enc")]
    TruncatedFile,
    #[error("unsupported format version (expected {expected}, got {got})")]
    UnsupportedVersion { expected: u8, got: u8 },
    #[error("ciphertext too short")]
    TruncatedCiphertext,
    #[error("decryption failed: wrong password or corrupted/tampered file")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("failed to derive key from password")]
    KeyDerivationFailed,
    #[error("failed to generate random salt")]
    RandomSaltFailed,
    #[error("invalid .env contents")]
    InvalidEnv,
    #[error("invalid keyfile")]
    InvalidKeyfile,
}
