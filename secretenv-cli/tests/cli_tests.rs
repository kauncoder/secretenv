//! Integration tests: run the real `secretenv` binary (`CARGO_BIN_EXE_secretenv`).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn secretenv_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_secretenv")
        .map(PathBuf::from)
        .expect("run tests with: cargo test -p secretenv-cli")
}

#[test]
fn encrypt_writes_enc_file_decrypt_prints_plaintext() {
    let dir = tempfile::tempdir().expect("tempdir");
    let plain_path = dir.path().join("app.env");
    let content = b"API_KEY=fake_key_123";
    fs::write(&plain_path, content).expect("write plain");

    let enc_path = PathBuf::from(format!("{}.enc", plain_path.display()));
    let password = "cli-test-password";

    let enc_status = Command::new(secretenv_bin())
        .args(["encrypt", plain_path.to_str().unwrap()])
        .env("SECRETENV_PASSWORD", password)
        .status()
        .expect("spawn encrypt");
    assert!(enc_status.success(), "encrypt failed");
    assert!(enc_path.exists(), ".enc file missing");

    let dec_output = Command::new(secretenv_bin())
        .args(["decrypt", enc_path.to_str().unwrap()])
        .env("SECRETENV_PASSWORD", password)
        .output()
        .expect("spawn decrypt");
    assert!(
        dec_output.status.success(),
        "decrypt failed: {:?}",
        dec_output.stderr
    );
    assert_eq!(dec_output.stdout.as_slice(), content);
}