use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn secretenv_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_secretenv")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../target/{profile}/secretenv"))
        })
}

fn set_stdin(password_file: &Path, enc_path: &Path, key: &str, value: &str) -> std::process::ExitStatus {
    let mut child = Command::new(secretenv_bin())
        .args([
            "--password-file",
            password_file.to_str().unwrap(),
            "set",
            enc_path.to_str().unwrap(),
            key,
            "--stdin",
        ])
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn set --stdin");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(value.as_bytes())
        .expect("write stdin");
    child.wait().expect("wait set")
}

#[test]
fn set_get_remove_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let enc_path = dir.path().join("app.env.enc");
    let password_path = dir.path().join("password.txt");
    std::fs::write(&password_path, b"cli-test-password\n").expect("write password file");

    let set_status = set_stdin(&password_path, &enc_path, "API_KEY", "fake_key_123");
    assert!(set_status.success(), "set failed");
    assert!(enc_path.exists(), ".enc file missing");

    let get_output = Command::new(secretenv_bin())
        .args([
            "--password-file",
            password_path.to_str().unwrap(),
            "get",
            enc_path.to_str().unwrap(),
            "API_KEY",
        ])
        .output()
        .expect("spawn get");
    assert!(
        get_output.status.success(),
        "get failed: {}",
        String::from_utf8_lossy(&get_output.stderr)
    );
    assert_eq!(get_output.stdout, b"fake_key_123");

    let list_output = Command::new(secretenv_bin())
        .args([
            "--password-file",
            password_path.to_str().unwrap(),
            "list",
            enc_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn list");
    assert!(list_output.status.success(), "list failed");
    assert_eq!(list_output.stdout, b"API_KEY\n");

    let remove_status = Command::new(secretenv_bin())
        .args([
            "--password-file",
            password_path.to_str().unwrap(),
            "remove",
            enc_path.to_str().unwrap(),
            "API_KEY",
        ])
        .status()
        .expect("spawn remove");
    assert!(remove_status.success(), "remove failed");

    let get_missing = Command::new(secretenv_bin())
        .args([
            "--password-file",
            password_path.to_str().unwrap(),
            "get",
            enc_path.to_str().unwrap(),
            "API_KEY",
        ])
        .status()
        .expect("spawn get after remove");
    assert!(!get_missing.success(), "get should fail after remove");
}

#[test]
fn export_keyfile_unlock_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let enc_path = dir.path().join("app.env.enc");
    let password_path = dir.path().join("password.txt");
    let keyfile_path = dir.path().join("vault.key");
    std::fs::write(&password_path, b"cli-test-password\n").expect("write password file");

    let set_status = set_stdin(&password_path, &enc_path, "TOKEN", "value-with-#-hash");
    assert!(set_status.success(), "set failed");

    let export_status = Command::new(secretenv_bin())
        .args([
            "--password-file",
            password_path.to_str().unwrap(),
            "export-key",
            enc_path.to_str().unwrap(),
            keyfile_path.to_str().unwrap(),
        ])
        .status()
        .expect("spawn export-key");
    assert!(export_status.success(), "export-key failed");
    assert!(keyfile_path.exists(), "keyfile missing");

    let get_output = Command::new(secretenv_bin())
        .args([
            "--keyfile",
            keyfile_path.to_str().unwrap(),
            "get",
            enc_path.to_str().unwrap(),
            "TOKEN",
        ])
        .output()
        .expect("spawn get with keyfile");
    assert!(
        get_output.status.success(),
        "get with keyfile failed: {}",
        String::from_utf8_lossy(&get_output.stderr)
    );
    assert_eq!(get_output.stdout, b"value-with-#-hash");

    let set_with_keyfile = {
        let mut child = Command::new(secretenv_bin())
            .args([
                "--keyfile",
                keyfile_path.to_str().unwrap(),
                "set",
                enc_path.to_str().unwrap(),
                "OTHER",
                "--stdin",
            ])
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn set with keyfile");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"still-works")
            .unwrap();
        child.wait().expect("wait")
    };
    assert!(set_with_keyfile.success(), "set with keyfile failed");

    let get_other = Command::new(secretenv_bin())
        .args([
            "--keyfile",
            keyfile_path.to_str().unwrap(),
            "get",
            enc_path.to_str().unwrap(),
            "OTHER",
        ])
        .output()
        .expect("spawn get other");
    assert!(get_other.status.success());
    assert_eq!(get_other.stdout, b"still-works");
}

#[test]
fn import_plaintext_env() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env_path = dir.path().join(".env");
    let enc_path = dir.path().join("app.env.enc");
    let password_path = dir.path().join("password.txt");
    std::fs::write(&env_path, b"API_KEY=from-dotenv\nHASH=val#ue\n").expect("write .env");
    std::fs::write(&password_path, b"import-test-password\n").expect("write password file");

    let status = Command::new(secretenv_bin())
        .args([
            "--password-file",
            password_path.to_str().unwrap(),
            "import",
            env_path.to_str().unwrap(),
            enc_path.to_str().unwrap(),
        ])
        .status()
        .expect("spawn import");
    assert!(status.success(), "import failed");
    assert!(enc_path.exists(), ".enc missing");
    assert!(env_path.exists(), "source should remain without --delete-source");

    let get_output = Command::new(secretenv_bin())
        .args([
            "--password-file",
            password_path.to_str().unwrap(),
            "get",
            enc_path.to_str().unwrap(),
            "API_KEY",
        ])
        .output()
        .expect("spawn get after import");
    assert!(get_output.status.success(), "get after import failed");
    assert_eq!(get_output.stdout, b"from-dotenv");
}

#[test]
fn import_gitignore_and_delete_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let init = Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .status()
        .expect("git init");
    if !init.success() {
        eprintln!("git not available; skipping import_gitignore_and_delete_source");
        return;
    }

    let env_path = dir.path().join(".env");
    let enc_path = dir.path().join("prod.env.enc");
    let key_path = dir.path().join("vault.key");
    let password_path = dir.path().join("password.txt");
    std::fs::write(&env_path, b"TOKEN=abc\n").expect("write .env");
    std::fs::write(&password_path, b"pw\n").expect("write password");

    let import = Command::new(secretenv_bin())
        .args([
            "--password-file",
            password_path.to_str().unwrap(),
            "import",
            "--gitignore",
            "--delete-source",
            env_path.to_str().unwrap(),
            enc_path.to_str().unwrap(),
        ])
        .status()
        .expect("spawn import");
    assert!(import.success(), "import with gitignore failed");
    assert!(!env_path.exists(), "source should be deleted");
    assert!(enc_path.exists());

    let gitignore = fs::read_to_string(dir.path().join(".gitignore")).expect("read gitignore");
    assert!(gitignore.contains(".env"));
    assert!(gitignore.contains("!*.env.enc"));
    assert!(gitignore.contains("*.key"));

    let export = Command::new(secretenv_bin())
        .args([
            "--password-file",
            password_path.to_str().unwrap(),
            "export-key",
            "--gitignore",
            enc_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        ])
        .status()
        .expect("spawn export-key");
    assert!(export.success(), "export-key --gitignore failed");

    let gitignore = fs::read_to_string(dir.path().join(".gitignore")).expect("read gitignore");
    assert!(gitignore.contains("vault.key"));
}

#[test]
fn export_keyfile_private_mode_on_unix() {
    #[cfg(not(unix))]
    return;

    let dir = tempfile::tempdir().expect("tempdir");
    let enc_path = dir.path().join("app.env.enc");
    let password_path = dir.path().join("password.txt");
    let keyfile_path = dir.path().join("vault.key");
    std::fs::write(&password_path, b"pw\n").expect("write password");

    assert!(set_stdin(&password_path, &enc_path, "K", "v").success());

    assert!(
        Command::new(secretenv_bin())
            .args([
                "--password-file",
                password_path.to_str().unwrap(),
                "export-key",
                enc_path.to_str().unwrap(),
                keyfile_path.to_str().unwrap(),
            ])
            .status()
            .expect("export-key")
            .success()
    );

    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(&keyfile_path).expect("metadata").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn set_rejects_argv_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let enc_path = dir.path().join("app.env.enc");
    let password_path = dir.path().join("password.txt");
    std::fs::write(&password_path, b"pw\n").expect("write password");

    let status = Command::new(secretenv_bin())
        .args([
            "--password-file",
            password_path.to_str().unwrap(),
            "set",
            enc_path.to_str().unwrap(),
            "API_KEY",
            "leaked-in-argv",
        ])
        .status()
        .expect("spawn set with argv value");
    assert!(!status.success(), "set should reject positional value");
}
