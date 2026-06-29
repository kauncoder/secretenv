use secrecy::{SecretBox, SecretString};

pub enum VaultUnlock {
    Password(SecretString),
    Key(SecretBox<Vec<u8>>),
}
