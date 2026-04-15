use anyhow::Error;
use argon2::password_hash::rand_core::RngCore;
use argon2::{Argon2};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce, aead::{Aead, AeadCore, KeyInit, OsRng, generic_array::GenericArray}
};

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
use rpassword::prompt_password;
use crate::constants::SALT_LEN;

pub fn get_password()->Result<SecretString, Error>{
    //for now we just generate a password but later we will get it from storage/prompt
    let password = prompt_password("enter password: ")
    .map_err(|e| Error::msg(e.to_string()))?;
    Ok(SecretString::new(password.into_boxed_str()))
}

pub fn random_salt()->Result<Vec<u8>,Error>{
    let mut salt = vec![0u8; SALT_LEN];
    OsRng.try_fill_bytes(&mut salt).map_err(|e|Error::msg(format!("failed while generating salt: {e}")))?;
    Ok(salt)
}

pub fn key_derivation(password: &SecretString, salt: &[u8]) -> Result<SecretBox<Vec<u8>>, Error> {

    let mut key = SecretBox::new(Box::new(vec![0u8; 32]));

    Argon2::default()
        .hash_password_into(password.expose_secret().as_bytes(), salt,key.expose_secret_mut())
        .map_err(|e| Error::msg(e.to_string()))?;
    Ok(key) 
}

pub fn encrypt_with_key(plaintext: SecretBox<Vec<u8>>, key: SecretBox<Vec<u8>>) -> Result<Vec<u8>, Error> {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); //// random, unique and can be public; 12 bytes
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key.expose_secret()));
    let ciphertext = cipher.encrypt(&nonce, plaintext.expose_secret().as_slice()).map_err(|e| Error::msg(e.to_string()))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}


pub fn decrypt_with_key(encypted_text: &[u8], key: SecretBox<Vec<u8>>)->Result<SecretBox<Vec<u8>>, Error>{
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key.expose_secret()));
    let nonce = Nonce::from_slice(&encypted_text[..12]);
    let ciphertext = &encypted_text[12..];
    let plaintext = SecretBox::new(Box::new(cipher.decrypt(nonce, ciphertext).map_err(|e| Error::msg(e.to_string()))?));
    Ok(plaintext)
}

pub fn decrypt_text(encypted_text: &[u8], password: &SecretString, salt: Vec<u8>)-> Result<SecretBox<Vec<u8>>, Error> {
    let key =  key_derivation(password, &salt)?;
    Ok(decrypt_with_key(encypted_text,key)?)
}