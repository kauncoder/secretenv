# secretenv

**v0.1** — encrypt a dotenv-style secrets file to `.env.enc` for local/CI use.

Workspace crates:

- **`secretenv-core`** — library (`EnvVault`, crypto, keyfiles)
- **`secretenv-cli`** — `secretenv` binary

## What it does

Store environment variables in an encrypted file instead of a plaintext `.env`. The CLI supports per-key `set` / `get` / `list` / `remove` without dumping the whole vault to stdout.

**Wire format (v1):** `version (1) || salt (16) || nonce (12) || ciphertext + Poly1305 tag`

**Crypto:** Argon2id (password unlock) → 32-byte key → ChaCha20-Poly1305 with AAD over `version || salt`.

**Limits:** max vault file size **256 KiB** (intended for env vars, not arbitrary file encryption).

## Build

```bash
cargo build --release
# binary: target/release/secretenv
```

## CLI quickstartI’m in Ask mode — if you want to remove/slim vcs and add a CI workflow + README section, switch to Agent mode and say which option you prefer (full removal vs keep tracked-check only).

### Password unlock (interactive)

```bash
# Store master password in OS keyring (keyed by vault's absolute path)
secretenv key set prod.env.enc

# Remove keyring entry for this vault path
secretenv key delete prod.env.enc

# Create / update secrets (prompts for value on a TTY)
secretenv set prod.env.enc API_KEY

# Scripts / CI: pass value on stdin (not argv); required when stdin is not a TTY
printf 'postgres://...\n' | secretenv set prod.env.enc DATABASE_URL --stdin
secretenv --password-file .secrets/pw set prod.env.enc API_KEY --stdin < secret.txt

secretenv list prod.env.enc
secretenv get prod.env.enc API_KEY          # warns on TTY; newline only on TTY
secretenv get prod.env.enc API_KEY --quiet  # suppress TTY warning
secretenv remove prod.env.enc OLD_KEY
```

### Import plaintext `.env` → `.env.enc`

```bash
# Encrypt existing .env into a new vault
secretenv import .env prod.env.enc

# Append .env, .env.*, !*.env.enc, *.key (and source path if not .env) to .gitignore
# inside a marked # >>> secretenv block (opt-in; requires git repo)
secretenv import .env prod.env.enc --gitignore

# After encrypt: gitignore + delete plaintext (verify with list/get first)
secretenv import .env prod.env.enc --gitignore --delete-source

# Overwrite existing vault, or import a git-tracked .env (fails otherwise)
secretenv import .env prod.env.enc --force

# Skip all .gitignore side effects
secretenv --no-vcs import .env prod.env.enc --gitignore
```

### Password file (CI / scripts)

```bash
printf 'secret\n' | secretenv --password-file .secrets/master-password set prod.env.enc API_KEY --stdin
secretenv --password-file .secrets/master-password get prod.env.enc API_KEY
```

Keep password files **out of git** and restrict permissions (`chmod 600`).

### Exported keyfile (CI without password)

```bash
# One-time: derive key from password + vault salt, write PEM keyfile
# (requires password unlock — not --keyfile)
secretenv export-key prod.env.enc vault.key

# Add keyfile path and *.key to .gitignore (opt-in)
secretenv export-key prod.env.enc vault.key --gitignore

# CI: unlock with keyfile (PEM or raw 32-byte file)
secretenv --keyfile vault.key get prod.env.enc API_KEY
```

`export-key` writes the keyfile with mode **0600** on Unix.

Unlock priority: `--keyfile` → `--password-file` → OS keyring → interactive prompt.

## Library usage

```rust
use secrecy::SecretString;
use secretenv_core::{EnvVault, VaultUnlock};

fn main() -> Result<(), secretenv_core::Error> {
    let unlock = VaultUnlock::Password(SecretString::new("master-password".into()));

    // Load encrypted blob
    let data = std::fs::read("prod.env.enc")?;
    let vault = EnvVault::decrypt_from_blob(&data, &unlock)?;

    if let Some(url) = vault.get("DATABASE_URL") {
        // use url.expose_secret()
    }

    // Modify and save (reuse salt so password/keyfile stay valid)
    let mut vault = vault;
    vault.set("API_KEY", SecretString::new("new-value".into()));
    let salt = EnvVault::vault_salt(&data)?;
    let blob = vault.encrypt_to_blob(&unlock, Some(&salt))?;
    std::fs::write("prod.env.enc", blob)?;

    Ok(())
}
```

Keyfile unlock:

```rust
use secrecy::SecretBox;
use secretenv_core::{import_keyfile, EnvVault, VaultUnlock};

let key = import_keyfile(&std::fs::read("vault.key")?)?;
let unlock = VaultUnlock::Key(key);
let vault = EnvVault::decrypt_from_blob(&data, &unlock)?;
```

Export key material (password path only):

```rust
use secrecy::SecretString;
use secretenv_core::{export_keyfile, EnvVault};

let data = std::fs::read("prod.env.enc")?;
let password = SecretString::new("master-password".into());
let key = EnvVault::derive_vault_key(&data, &password)?;
let pem = export_keyfile(key.expose_secret());
std::fs::write("vault.key", pem)?;
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions("vault.key", std::fs::Permissions::from_mode(0o600))?;
}
```


## Security analysis

> Stub — threat model and issue tracking TBD.

### Threat model

| Area | Notes |
|------|-------|
| In scope | TBD |
| Out of scope | TBD |
| Operational cautions | TBD |

### Security issues

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| | | | |

### Design issues

| ID | Issue | Status |
|----|-------|--------|
| | | |

## Known limitations

| Severity | Issue | Notes |
|----------|-------|-------|
| | | |


## License

MIT — see [LICENSE](LICENSE).