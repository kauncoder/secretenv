use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::env;
use secretenv_core::key_management::{self, KEYRING_USER_DEFAULT};

#[derive(Parser)]
#[command(name = "secretenv", version, about = "encrypt .env to .env.enc; decrypt to stdout only")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // Read plaintext file, write encrypted blob (default: <path>.enc)
    Encrypt {
        path: PathBuf,
        #[arg(long = "output", value_name = "FILE")]
        output: Option<PathBuf>,
    },
    // Read encrypted file, print plaintext to stdout (no disk write)
    Decrypt {
        path: PathBuf,
    },
}

// fn prompt_password() -> Result<SecretString> {
//     let p = rpassword::prompt_password("Password: ").context("read password")?;
//     Ok(SecretString::new(p.into_boxed_str()))
// }



fn resolve_password() -> Result<SecretString> {
    // 1) Environment variable (good for CI / automation)
    if let Ok(p) = env::var("SECRETENV_PASSWORD") {
        if !p.is_empty() {
            return Ok(SecretString::new(p.into_boxed_str()));
        }
    }
    // 2) OS keyring (Linux Secret Service, macOS Keychain, Windows Credential Manager)
    if let Some(p) = key_management::load_from_keyring(KEYRING_USER_DEFAULT)
        .context("load password from keyring")?
    {
        return Ok(p);
    }
    // 3) Interactive prompt fallback
    let p = rpassword::prompt_password("Password: ").context("read password")?;
    Ok(SecretString::new(p.into_boxed_str()))
}


fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt { path, output } => {
            let bytes = fs::read(&path)
                .with_context(|| format!("read {}", path.display()))?;
            let plaintext = SecretBox::new(Box::new(bytes));
            let pwd = resolve_password()?;
            let blob = secretenv_core::format::encode(plaintext, &pwd)?;

            let out_path =
                output.unwrap_or_else(|| PathBuf::from(format!("{}.enc", path.display())));
            fs::write(&out_path, &blob)
                .with_context(|| format!("write {}", out_path.display()))?;
            eprintln!("wrote {}", out_path.display());
        }
        Commands::Decrypt { path } => {
            let blob = fs::read(&path)
                .with_context(|| format!("read {}", path.display()))?;
            let pwd = resolve_password()?;
            let plaintext = secretenv_core::format::decode(&blob, &pwd)?;
            io::stdout()
                .write_all(plaintext.expose_secret())
                .context("write stdout")?;
        }
    }
    Ok(())
}