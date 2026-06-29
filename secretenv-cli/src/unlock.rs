use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use secrecy::SecretString;
use secretenv_core::{import_keyfile, VaultUnlock};

use crate::key_management;

pub struct UnlockOptions<'a> {
    pub password_file: Option<&'a Path>,
    pub keyfile: Option<&'a Path>,
}

pub fn resolve_unlock(vault_id: &str, opts: UnlockOptions<'_>) -> Result<VaultUnlock> {
    if opts.password_file.is_some() && opts.keyfile.is_some() {
        anyhow::bail!("use only one of --password-file or --keyfile");
    }

    if let Some(path) = opts.keyfile {
        let bytes =
            fs::read(path).with_context(|| format!("read keyfile {}", path.display()))?;
        let key = import_keyfile(&bytes)
            .map_err(anyhow::Error::new)
            .context("parse keyfile")?;
        return Ok(VaultUnlock::Key(key));
    }

    if let Some(path) = opts.password_file {
        let bytes = fs::read(path)
            .with_context(|| format!("read password file {}", path.display()))?;
        let password = String::from_utf8(bytes).context("password file must be valid UTF-8")?;
        let password = password.trim_end_matches(['\n', '\r']).to_owned();
        if password.is_empty() {
            anyhow::bail!("password file is empty");
        }
        return Ok(VaultUnlock::Password(SecretString::new(
            password.into_boxed_str(),
        )));
    }

    if let Some(password) =
        key_management::load_from_keyring(vault_id).context("load password from keyring")?
    {
        return Ok(VaultUnlock::Password(password));
    }

    let password =
        rpassword::prompt_password("Password: ").context("read password from prompt")?;
    Ok(VaultUnlock::Password(SecretString::new(
        password.into_boxed_str(),
    )))
}
