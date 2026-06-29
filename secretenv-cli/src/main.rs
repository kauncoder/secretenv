use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use secretenv_core::{export_keyfile, EnvVault, VaultUnlock};
use tempfile::NamedTempFile;

mod key_management;
mod unlock;
mod vcs;

#[derive(Parser)]
#[command(name = "secretenv", version, about = "manage encrypted .env.enc files")]
struct Cli {
    #[arg(
        long = "password-file",
        value_name = "FILE",
        global = true,
        conflicts_with = "keyfile"
    )]
    password_file: Option<PathBuf>,
    #[arg(long = "keyfile", value_name = "FILE", global = true)]
    keyfile: Option<PathBuf>,
    #[arg(long = "no-vcs", global = true, help = "skip .gitignore updates")]
    no_vcs: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a plaintext dotenv file into a new .env.enc vault.
    Import {
        source: PathBuf,
        dest: PathBuf,
        #[arg(long, help = "append .env / keyfile patterns to .gitignore")]
        gitignore: bool,
        #[arg(long, help = "delete source .env after successful encrypt")]
        delete_source: bool,
        #[arg(long, help = "overwrite existing dest or import tracked source")]
        force: bool,
    },
    Set {
        file: PathBuf,
        key: String,
        #[arg(
            long,
            help = "read secret value from stdin (use in scripts; avoids argv leaks)"
        )]
        stdin: bool,
    },
    Get {
        file: PathBuf,
        key: String,
        #[arg(long, help = "suppress stderr warning when writing secret to a terminal")]
        quiet: bool,
    },
    List {
        file: PathBuf,
    },
    Remove {
        file: PathBuf,
        key: String,
    },
    ExportKey {
        file: PathBuf,
        output: PathBuf,
        #[arg(long, help = "append keyfile path and *.key to .gitignore")]
        gitignore: bool,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    Set { file: PathBuf },
    Delete { file: PathBuf },
}

fn vault_id(path: &Path) -> Result<String> {
    let absolute = if path.exists() {
        fs::canonicalize(path)
    } else {
        let parent = path.parent().unwrap_or(Path::new("."));
        let parent = fs::canonicalize(parent).or_else(|_| {
            fs::canonicalize(".").map(|cwd| {
                if parent.as_os_str().is_empty() {
                    cwd
                } else {
                    cwd.join(parent)
                }
            })
        })?;
        Ok(parent.join(
            path.file_name()
                .context("vault path must include a file name")?,
        ))
    }?;
    Ok(absolute.to_string_lossy().into_owned())
}

fn existing_salt(path: &Path) -> Result<Option<Vec<u8>>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(Some(
        EnvVault::vault_salt(&data).map_err(anyhow::Error::new)?,
    ))
}

fn load_vault(path: &Path, unlock: &VaultUnlock) -> Result<EnvVault> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    EnvVault::decrypt_from_blob(&data, unlock)
        .map_err(anyhow::Error::new)
        .context("open vault")
}

fn atomic_write(path: &Path, data: &[u8], private: bool) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut tmp = NamedTempFile::new_in(parent).context("create temp file")?;
    tmp.write_all(data).context("write temp file")?;
    tmp.as_file().sync_all().context("sync temp file")?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .context("set temp file mode 0600")?;
    }
    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("replace {}", path.display()))?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set mode 0600 on {}", path.display()))?;
    }
    Ok(())
}

fn save_vault(path: &Path, vault: &EnvVault, unlock: &VaultUnlock) -> Result<()> {
    let salt = existing_salt(path)?;
    let blob = vault
        .encrypt_to_blob(unlock, salt.as_deref())
        .map_err(anyhow::Error::new)
        .context("encrypt vault")?;
    atomic_write(path, &blob, false)?;
    Ok(())
}

fn open_or_create(path: &Path, unlock: &VaultUnlock) -> Result<EnvVault> {
    if path.exists() {
        load_vault(path, unlock)
    } else {
        Ok(EnvVault::new())
    }
}

fn write_stdout_value(value: &SecretString, quiet: bool) -> Result<()> {
    if io::stdout().is_terminal() && !quiet {
        eprintln!("warning: writing secret to terminal (redirect stdout in scripts)");
    }
    io::stdout()
        .write_all(value.expose_secret().as_bytes())
        .context("write stdout")?;
    if io::stdout().is_terminal() {
        io::stdout().write_all(b"\n").context("write stdout")?;
    }
    Ok(())
}

fn resolve_set_value(stdin_flag: bool) -> Result<SecretString> {
    if stdin_flag {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("read value from stdin")?;
        let value = buf.trim_end_matches(['\n', '\r']);
        if value.is_empty() {
            anyhow::bail!("empty value from stdin");
        }
        return Ok(SecretString::new(value.into()));
    }
    if !io::stdin().is_terminal() {
        anyhow::bail!("stdin is not a terminal; pass --stdin to read the value from stdin");
    }
    let value = rpassword::prompt_password("Value: ").context("read value")?;
    Ok(SecretString::new(value.into_boxed_str()))
}

fn import_env(
    source: &Path,
    dest: &Path,
    unlock: &VaultUnlock,
    gitignore: bool,
    delete_source: bool,
    force: bool,
) -> Result<()> {
    if !source.is_file() {
        anyhow::bail!("source file not found: {}", source.display());
    }
    if dest.exists() && !force {
        anyhow::bail!(
            "{} already exists; use --force to overwrite",
            dest.display()
        );
    }

    if !force {
        if let Some(repo_root) = vcs::git_root(source) {
            let source_abs = fs::canonicalize(source)
                .with_context(|| format!("resolve {}", source.display()))?;
            if vcs::is_tracked(&source_abs, &repo_root)? {
                anyhow::bail!(
                    "{} is tracked by git; remove it from the index first or pass --force",
                    vcs::path_relative_to_repo(&source_abs, &repo_root)
                );
            }
        }
    }

    let plain = fs::read(source).with_context(|| format!("read {}", source.display()))?;
    let vault = EnvVault::from_plaintext(SecretBox::new(Box::new(plain)))
        .map_err(anyhow::Error::new)
        .context("parse dotenv source")?;
    let blob = vault
        .encrypt_to_blob(unlock, None)
        .map_err(anyhow::Error::new)
        .context("encrypt vault")?;
    atomic_write(dest, &blob, false)?;
    eprintln!("encrypted {} → {}", source.display(), dest.display());

    if gitignore {
        vcs::apply_import_gitignore(source)?;
    }

    if delete_source {
        fs::remove_file(source)
            .with_context(|| format!("delete {}", source.display()))?;
        eprintln!("deleted {}", source.display());
    } else if gitignore {
        eprintln!("plaintext {} kept on disk", source.display());
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let password_file = cli.password_file.clone();
    let keyfile = cli.keyfile.clone();
    let no_vcs = cli.no_vcs;
    let opts = unlock::UnlockOptions {
        password_file: password_file.as_deref(),
        keyfile: keyfile.as_deref(),
    };
    match cli.command {
        Commands::Import {
            source,
            dest,
            gitignore,
            delete_source,
            force,
        } => {
            let vault_id = vault_id(&dest)?;
            let unlock = unlock::resolve_unlock(&vault_id, opts)?;
            import_env(
                &source,
                &dest,
                &unlock,
                gitignore && !no_vcs,
                delete_source,
                force,
            )?;
        }
        Commands::Set { file, key, stdin } => {
            let vault_id = vault_id(&file)?;
            let unlock = unlock::resolve_unlock(&vault_id, opts)?;
            let mut vault = open_or_create(&file, &unlock)?;
            let value = resolve_set_value(stdin)?;
            vault.set(key, value);
            save_vault(&file, &vault, &unlock)?;
            eprintln!("wrote {}", file.display());
        }
        Commands::Get { file, key, quiet } => {
            let vault_id = vault_id(&file)?;
            let unlock = unlock::resolve_unlock(&vault_id, opts)?;
            let vault = load_vault(&file, &unlock)?;
            let value = vault
                .get(&key)
                .with_context(|| format!("key not found: {key}"))?;
            write_stdout_value(value, quiet)?;
        }
        Commands::List { file } => {
            let vault_id = vault_id(&file)?;
            let unlock = unlock::resolve_unlock(&vault_id, opts)?;
            let vault = load_vault(&file, &unlock)?;
            for key in vault.list_keys() {
                println!("{key}");
            }
        }
        Commands::Remove { file, key } => {
            let vault_id = vault_id(&file)?;
            let unlock = unlock::resolve_unlock(&vault_id, opts)?;
            let mut vault = load_vault(&file, &unlock)?;
            if !vault.remove(&key) {
                anyhow::bail!("key not found: {key}");
            }
            save_vault(&file, &vault, &unlock)?;
            eprintln!("removed {key} from {}", file.display());
        }
        Commands::ExportKey {
            file,
            output,
            gitignore,
        } => {
            if keyfile.is_some() {
                anyhow::bail!(
                    "export-key requires a password (--password-file or keyring), not --keyfile"
                );
            }
            let vault_id = vault_id(&file)?;
            let unlock = unlock::resolve_unlock(&vault_id, opts)?;
            let VaultUnlock::Password(password) = unlock else {
                anyhow::bail!("export-key requires a password");
            };
            let data = fs::read(&file).with_context(|| format!("read {}", file.display()))?;
            let key = EnvVault::derive_vault_key(&data, &password)
                .map_err(anyhow::Error::new)
                .context("derive vault key")?;
            let pem = export_keyfile(key.expose_secret());
            atomic_write(&output, &pem, true)?;
            eprintln!("exported key to {}", output.display());
            if gitignore && !no_vcs {
                vcs::apply_keyfile_gitignore(&output)?;
            }
        }
        Commands::Key { command } => match command {
            KeyCommands::Set { file } => {
                let vault_id = vault_id(&file)?;
                let password = prompt_password_once()?;
                key_management::store_to_keyring(&vault_id, &password)?;
                eprintln!("stored keyring entry for {}", vault_id);
            }
            KeyCommands::Delete { file } => {
                let vault_id = vault_id(&file)?;
                key_management::delete_from_keyring(&vault_id)?;
                eprintln!("deleted keyring entry for {}", vault_id);
            }
        },
    }
    Ok(())
}

fn prompt_password_once() -> Result<SecretString> {
    let password = rpassword::prompt_password("Password: ").context("read password")?;
    Ok(SecretString::new(password.into_boxed_str()))
}
