//! Store and load the secretenv master password via the OS credential store.

use anyhow::{Context, Result};
use keyring::Entry;
use secrecy::{ExposeSecret, SecretString};

pub const KEYRING_SERVICE: &str = "secretenv";

fn entry(user: &str) -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, user).context("create keyring entry")
}

pub fn load_from_keyring(user: &str) -> Result<Option<SecretString>> {
    let e = entry(user)?;
    match e.get_password() {
        Ok(s) => Ok(Some(SecretString::new(s.into_boxed_str()))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e).context("read keyring"),
    }
}

pub fn store_to_keyring(user: &str, password: &SecretString) -> Result<()> {
    let e = entry(user)?;
    e.set_password(password.expose_secret())
        .context("write keyring")
}

pub fn delete_from_keyring(user: &str) -> Result<()> {
    let e = entry(user)?;
    e.delete_credential().context("delete keyring entry")
}
