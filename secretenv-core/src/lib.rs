mod constants;
mod crypto;
mod error;
mod format;

pub use error::Error;
use secrecy::{SecretBox, SecretString};

/// How to unlock or seal a vault.
pub enum VaultUnlock {
    Password(SecretString),
    Key(SecretBox<Vec<u8>>),
}

pub fn encrypt(plaintext: SecretBox<Vec<u8>>, password: &SecretString) -> Result<Vec<u8>, Error> {
    format::encode(plaintext, &VaultUnlock::Password(password.clone()), None)
}

pub fn decrypt(data: &[u8], password: &SecretString) -> Result<SecretBox<Vec<u8>>, Error> {
    format::decode(data, &VaultUnlock::Password(password.clone()))
}

pub fn vault_salt(data: &[u8]) -> Result<Vec<u8>, Error> {
    format::salt_from_blob(data)
}

pub fn derive_vault_key(data: &[u8], password: &SecretString) -> Result<SecretBox<Vec<u8>>, Error> {
    format::derive_key_from_password(data, password)
}
