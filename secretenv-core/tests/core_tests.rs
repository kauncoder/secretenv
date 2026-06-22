use secrecy::{ExposeSecret, SecretBox, SecretString};
use secretenv_core::Error;
use secretenv_core::{decrypt, encrypt};

fn test_password() -> SecretString {
    SecretString::new(Box::from("test-password"))
}

#[test]
fn encode_decode_round_trip() {
    let password = test_password();
    let expected = b"test_plain_text";

    let plaintext = SecretBox::new(Box::new(expected.to_vec()));
    let blob = encrypt(plaintext, &password).unwrap();
    let output = decrypt(&blob, &password).unwrap();
    assert_eq!(expected, output.expose_secret().as_slice());
}

#[test]
fn truncated_file() {
    let password = test_password();
    let err = decrypt(&[1u8; 4], &password).unwrap_err();
    assert_eq!(err, Error::TruncatedFile);
}

#[test]
fn wrong_password() {
    let password = test_password();
    let plaintext = SecretBox::new(Box::new(b"secret".to_vec()));
    let blob = encrypt(plaintext, &password).unwrap();

    let wrong = SecretString::new(Box::from("wrong-password"));
    let err = decrypt(&blob, &wrong).unwrap_err();
    assert_eq!(err, Error::DecryptionFailed);
}

#[test]
fn bit_flip_in_ciphertext() {
    let password = test_password();
    let plaintext = SecretBox::new(Box::new(b"secret".to_vec()));
    let mut blob = encrypt(plaintext, &password).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 1;

    let err = decrypt(&blob, &password).unwrap_err();
    assert_eq!(err, Error::DecryptionFailed);
}

#[test]
fn bit_flip_in_salt() {
    let password = test_password();
    let plaintext = SecretBox::new(Box::new(b"secret".to_vec()));
    let mut blob = encrypt(plaintext, &password).unwrap();
    blob[1] ^= 1;

    let err = decrypt(&blob, &password).unwrap_err();
    assert_eq!(err, Error::DecryptionFailed);
}

#[test]
fn bit_flip_in_version() {
    let password = test_password();
    let plaintext = SecretBox::new(Box::new(b"secret".to_vec()));
    let mut blob = encrypt(plaintext, &password).unwrap();
    blob[0] ^= 1;

    let err = decrypt(&blob, &password).unwrap_err();
    assert_eq!(
        err,
        Error::UnsupportedVersion {
            expected: 1,
            got: 0
        }
    );
}
