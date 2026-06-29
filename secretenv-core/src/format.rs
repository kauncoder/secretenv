//! Wire format: `version (1) || salt (16) || nonce (12) || ciphertext+tag`

use secrecy::{ExposeSecret, SecretBox, SecretString};

use crate::constants::{current_format, format_from_version, FormatProfile, MAX_VAULT_FILE_BYTES, VERSION};
use crate::crypto::{self, random_salt};
use crate::error::Error;
use crate::unlock::VaultUnlock;

pub type Result<T> = std::result::Result<T, Error>;

fn format_from_blob(data: &[u8]) -> std::result::Result<&'static FormatProfile, Error> {
    if data.is_empty() {
        return Err(Error::TruncatedFile);
    }
    format_from_version(data[0]).ok_or(Error::UnsupportedVersion {
        expected: VERSION,
        got: data[0],
    })
}

fn header_bytes(format: &FormatProfile, salt: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(format.header_len());
    header.push(format.version);
    header.extend_from_slice(salt);
    header
}

fn resolve_key(
    unlock: &VaultUnlock,
    salt: &[u8],
    format: &FormatProfile,
) -> Result<SecretBox<Vec<u8>>> {
    match unlock {
        VaultUnlock::Password(password) => crypto::key_derivation(password, salt, format),
        VaultUnlock::Key(key) => Ok(SecretBox::new(Box::new(key.expose_secret().clone()))),
    }
}

pub(crate) fn salt_from_blob(data: &[u8]) -> Result<Vec<u8>> {
    let format: &FormatProfile = format_from_blob(data)?;
    if data.len() < format.min_file_len() {
        return Err(Error::TruncatedFile);
    }
    let start = format.salt_offset();
    Ok(data[start..start + format.salt_len()].to_vec())
}

pub(crate) fn encode(
    plaintext: SecretBox<Vec<u8>>,
    unlock: &VaultUnlock,
    existing_salt: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let format = current_format();
    let plaintext_len = plaintext.expose_secret().len();
    if plaintext_len > format.max_plaintext_bytes(MAX_VAULT_FILE_BYTES) {
        return Err(Error::ExceededVaultSizeLimit {
            max: MAX_VAULT_FILE_BYTES,
            got: format.encrypted_blob_len(plaintext_len),
        });
    }
    let salt = match existing_salt {
        Some(s) if s.len() == format.salt_len() => s.to_vec(),
        Some(_) => return Err(Error::EncryptionFailed),
        None => random_salt(format)?,
    };
    let header = header_bytes(format, &salt);
    let key = resolve_key(unlock, &salt, format)?;
    let payload = crypto::encrypt_with_key(plaintext, key, &header)?;
    let mut out = Vec::with_capacity(format.header_len() + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub(crate) fn decode(data: &[u8], unlock: &VaultUnlock) -> Result<SecretBox<Vec<u8>>> {
    if data.len() > MAX_VAULT_FILE_BYTES {
        return Err(Error::ExceededVaultSizeLimit {
            max: MAX_VAULT_FILE_BYTES,
            got: data.len(),
        });
    }
    let format = format_from_blob(data)?;
    if data.len() < format.min_file_len() {
        return Err(Error::TruncatedFile);
    }

    let header = &data[format.version_offset()..format.encrypted_payload_offset()];
    let salt = &data[format.salt_offset()..format.encrypted_payload_offset()];
    let payload = &data[format.encrypted_payload_offset()..];

    let key = resolve_key(unlock, salt, format)?;
    crypto::decrypt_with_key(payload, key, header, format)
}

pub(crate) fn derive_key_from_password(
    data: &[u8],
    password: &SecretString,
) -> Result<SecretBox<Vec<u8>>> {
    let format = format_from_blob(data)?;
    let salt = salt_from_blob(data)?;
    crypto::key_derivation(password, &salt, format)
}
