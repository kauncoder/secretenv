//! Binary layout for encoded text (no files yet).
//! This adds cersioning to the file
//! `version (1) || salt (16) || nonce (12) || ciphertext`

use anyway::Error;
use secrecy::{SecretBox, SecretString};
use crate::crypto::{self, random_salt};
use crate::constants::{VERSION,SALT_LEN};
// const VERSION: u8 = 1;
// const SALT_LEN: usize = 16; 
/// Minimum: version + salt + nonce + Poly1305 tag (even for empty plaintext).
const MIN_FILE_LEN: usize = VERSION as usize + SALT_LEN + 12 + 16;

pub fn encode(plaintext: SecretBox<Vec<u8>>, password: &SecretString) -> Result<Vec<u8>, Error> {
    // let mut salt = [0u8; SALT_LEN];
    // rand::rngs::OsRng.fill_bytes(&mut salt);
    let salt = random_salt()?;
    let key = crypto::key_derivation(password, &salt)?;
    let payload = crypto::encrypt_with_key(plaintext, key)?;
    let mut out = Vec::with_capacity(1 + SALT_LEN + payload.len());
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode(data: &[u8], password: &SecretString) -> Result<SecretBox<Vec<u8>>, Error> {
    if data.len() < MIN_FILE_LEN {
        return Err(Error::msg("truncated or invalid .env.enc"));
    }
    if data[0] != VERSION {
        return Err(Error::msg("unsupported format version"));
    }

    let salt = &data[1..1 + SALT_LEN];
    let payload = &data[1 + SALT_LEN..];

    let key = crypto::key_derivation(password, salt)?;
    crypto::decrypt_with_key(payload, key)
}
