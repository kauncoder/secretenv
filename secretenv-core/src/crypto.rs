use argon2::password_hash::rand_core::RngCore;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305, Nonce,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};

use crate::constants::{Argon2Params, FormatProfile};
use crate::error::Error;

pub(crate) type Result<T> = std::result::Result<T, Error>;

fn argon2(profile: &Argon2Params) -> Result<Argon2<'static>> {
    let params = Params::new(
        profile.m_cost,
        profile.t_cost,
        profile.p_cost,
        profile.output_len,
    )
    .map_err(|_| Error::KeyDerivationFailed)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub(crate) fn random_salt(format: &FormatProfile) -> Result<Vec<u8>> {
    let mut salt = vec![0u8; format.salt_len()];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| Error::RandomSaltFailed)?;
    Ok(salt)
}

pub(crate) fn key_derivation(
    password: &SecretString,
    salt: &[u8],
    format: &FormatProfile,
) -> Result<SecretBox<Vec<u8>>> {
    let key_len = format.key_len().ok_or(Error::KeyDerivationFailed)?;
    let mut key = SecretBox::new(Box::new(vec![0u8; key_len]));
    argon2(format.argon2())?
        .hash_password_into(
            password.expose_secret().as_bytes(),
            salt,
            key.expose_secret_mut(),
        )
        .map_err(|_| Error::KeyDerivationFailed)?;
    Ok(key)
}

pub(crate) fn encrypt_with_key(
    plaintext: SecretBox<Vec<u8>>,
    key: SecretBox<Vec<u8>>,
    aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.expose_secret()));
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.expose_secret().as_slice(),
                aad,
            },
        )
        .map_err(|_| Error::EncryptionFailed)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub(crate) fn decrypt_with_key(
    encrypted_text: &[u8],
    key: SecretBox<Vec<u8>>,
    aad: &[u8],
    format: &FormatProfile,
) -> Result<SecretBox<Vec<u8>>> {
    if encrypted_text.len() < format.min_encrypted_payload_len() {
        return Err(Error::TruncatedCiphertext);
    }
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key.expose_secret()));
    let nonce = Nonce::from_slice(&encrypted_text[..format.nonce_len()]);
    let ciphertext = &encrypted_text[format.nonce_len()..];
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::DecryptionFailed)?;
    Ok(SecretBox::new(Box::new(plaintext)))
}
