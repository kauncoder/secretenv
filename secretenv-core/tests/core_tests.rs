use secrecy::{ExposeSecret, SecretBox, SecretString};
use secretenv_core::crypto::{self};
use anyway::Error;

#[test]
fn test_encrypt_decrypt()->Result<(),Error> {
    let password = SecretString::new(Box::from("mypassword"));
    let expected_text = b"plaintext";
    let plaintext = SecretBox::new(Box::new(expected_text.to_vec()));
    let (ciphertext,salt) = crypto::encrypt_text(plaintext,&password)?;
    let decrypted = crypto::decrypt_text(&ciphertext, &password,salt)?;
    assert_eq!(expected_text, decrypted.expose_secret().as_slice());
    Ok(())
}