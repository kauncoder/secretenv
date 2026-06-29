use secrecy::{ExposeSecret, SecretString};
use secretenv_core::{EnvVault, Error, MAX_VAULT_FILE_BYTES, VaultUnlock};

const PLAINTEXT_OVERHEAD: usize = 45;

fn test_password() -> SecretString {
    SecretString::new(Box::from("test-password"))
}

fn unlock(password: &SecretString) -> VaultUnlock {
    VaultUnlock::Password(password.clone())
}

fn encrypt_test_blob(password: &SecretString) -> Vec<u8> {
    let mut vault = EnvVault::new();
    vault.set("X", SecretString::new(Box::from("secret")));
    vault.encrypt_to_blob(&unlock(password), None).unwrap()
}

#[test]
fn encode_decode_round_trip() {
    let password = test_password();
    let u = unlock(&password);

    let mut vault = EnvVault::new();
    vault.set("MSG", SecretString::new(Box::from("test_plain_text")));
    let blob = vault.encrypt_to_blob(&u, None).unwrap();

    let out = EnvVault::decrypt_from_blob(&blob, &u).unwrap();
    assert_eq!(out.get("MSG").unwrap().expose_secret(), "test_plain_text");
}

#[test]
fn truncated_file() {
    let err = EnvVault::decrypt_from_blob(&[1u8; 4], &unlock(&test_password()))
        .err()
        .expect("expected TruncatedFile");
    assert_eq!(err, Error::TruncatedFile);
}

#[test]
fn wrong_password() {
    let password = test_password();
    let blob = encrypt_test_blob(&password);

    let wrong = VaultUnlock::Password(SecretString::new(Box::from("wrong-password")));
    let err = EnvVault::decrypt_from_blob(&blob, &wrong)
        .err()
        .expect("expected DecryptionFailed");
    assert_eq!(err, Error::DecryptionFailed);
}

#[test]
fn corrupted_ciphertext() {
    let password = test_password();
    let mut blob = encrypt_test_blob(&password);
    *blob.last_mut().unwrap() ^= 1;

    let err = EnvVault::decrypt_from_blob(&blob, &unlock(&password))
        .err()
        .expect("expected DecryptionFailed");
    assert_eq!(err, Error::DecryptionFailed);
}

#[test]
fn corrupted_salt() {
    let password = test_password();
    let mut blob = encrypt_test_blob(&password);
    blob[1] ^= 1;

    let err = EnvVault::decrypt_from_blob(&blob, &unlock(&password))
        .err()
        .expect("expected DecryptionFailed");
    assert_eq!(err, Error::DecryptionFailed);
}

#[test]
fn corrupted_versioning() {
    let password = test_password();
    let mut blob = encrypt_test_blob(&password);
    blob[0] ^= 1;

    let err = EnvVault::decrypt_from_blob(&blob, &unlock(&password))
        .err()
        .expect("expected UnsupportedVersion");
    assert_eq!(
        err,
        Error::UnsupportedVersion {
            expected: 1,
            got: 0,
        }
    );
}

#[test]
fn encrypt_rejects_oversized_plaintext() {
    let password = test_password();
    let u = unlock(&password);
    let max_plaintext = MAX_VAULT_FILE_BYTES - PLAINTEXT_OVERHEAD;
    // Serialized as "K=" + value + "\n" → value_len + 3 bytes plaintext
    let mut vault = EnvVault::new();
    vault.set(
        "K",
        SecretString::new(Box::from(String::from_utf8(vec![b'x'; max_plaintext - 2]).unwrap())),
    );
    let err = vault
        .encrypt_to_blob(&u, None)
        .err()
        .expect("expected size error");
    assert_eq!(
        err,
        Error::ExceededVaultSizeLimit {
            max: MAX_VAULT_FILE_BYTES,
            got: MAX_VAULT_FILE_BYTES + 1,
        }
    );
}

#[test]
fn encrypt_at_size_limit_round_trips() {
    let password = test_password();
    let u = unlock(&password);
    let max_plaintext = MAX_VAULT_FILE_BYTES - PLAINTEXT_OVERHEAD;
    let value_len = max_plaintext.saturating_sub(3);
    let mut vault = EnvVault::new();
    vault.set(
        "K",
        SecretString::new(Box::from(String::from_utf8(vec![b'v'; value_len]).unwrap())),
    );
    let blob = vault.encrypt_to_blob(&u, None).unwrap();
    assert!(blob.len() <= MAX_VAULT_FILE_BYTES);
    let again = EnvVault::decrypt_from_blob(&blob, &u).unwrap();
    assert_eq!(again.get("K").unwrap().expose_secret().len(), value_len);
}

#[test]
fn decrypt_rejects_oversized_blob() {
    let oversize = vec![0u8; MAX_VAULT_FILE_BYTES + 1];
    let err = EnvVault::decrypt_from_blob(&oversize, &unlock(&test_password()))
        .err()
        .expect("expected size error");
    assert_eq!(
        err,
        Error::ExceededVaultSizeLimit {
            max: MAX_VAULT_FILE_BYTES,
            got: MAX_VAULT_FILE_BYTES + 1,
        }
    );
}
