use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretBox, SecretString};

#[derive(Parser)]
#[command(name = "secretenv", version, about = "Encrypt .env to .env.enc; decrypt to stdout only")]
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

fn prompt_password() -> Result<SecretString> {
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
            let pwd = prompt_password()?;
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
            let pwd = prompt_password()?;
            let plaintext = secretenv_core::format::decode(&blob, &pwd)?;
            io::stdout()
                .write_all(plaintext.expose_secret())
                .context("write stdout")?;
        }
    }
    Ok(())
}