use secrecy::{ExposeSecret, SecretBox, SecretString};
use anyhow::Error;
use secretenv_core::format::{encode,decode};

fn gen_test_password() -> SecretString {
    SecretString::new(Box::from("test-password"))
}

#[test]
fn encode_decode_round_trip() -> Result<(), Error> {
    let password = gen_test_password();
    let expected_plaintext :&[u8] = b"test_plain_text";
    let unexpected_plaintext :&[u8] = b"test_plain_text_bad";

    let plaintext = SecretBox::new(Box::new(expected_plaintext.to_vec()));
    let encrypted_blob = encode(plaintext, &password)?;
    let plaintext_output = decode(&encrypted_blob, &password)?;
    assert_eq!(expected_plaintext, plaintext_output.expose_secret());
    assert_ne!(unexpected_plaintext, plaintext_output.expose_secret());
    Ok(())
}