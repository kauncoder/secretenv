use std::collections::HashMap;
use std::io::Cursor;

use secrecy::{ExposeSecret, SecretBox, SecretString};

use crate::error::Error;
use crate::format;
use crate::unlock::VaultUnlock;

pub struct EnvVault(HashMap<String, SecretString>);

impl EnvVault {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn get(&self, key: &str) -> Option<&SecretString> {
        self.0.get(key)
    }

    pub fn set(&mut self, k: impl Into<String>, value: SecretString) {
        self.0.insert(k.into(), value);
    }

    pub fn remove(&mut self, k: &str) -> bool {
        self.0.remove(k).is_some()
    }

    pub fn list_keys(&self) -> Vec<&str> {
        let mut keys: Vec<&str> = self.0.keys().map(|k| k.as_str()).collect();
        keys.sort();
        keys
    }

    pub fn encrypt_to_blob(
        &self,
        unlock: &VaultUnlock,
        existing_salt: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        format::encode(serialize_plaintext(self), unlock, existing_salt)
    }

    pub fn decrypt_from_blob(data: &[u8], unlock: &VaultUnlock) -> Result<Self, Error> {
        Self::from_plaintext(format::decode(data, unlock)?)
    }

    pub fn from_plaintext(plaintext: SecretBox<Vec<u8>>) -> Result<Self, Error> {
        Ok(Self(parse_plaintext(plaintext)?))
    }

    pub fn vault_salt(data: &[u8]) -> Result<Vec<u8>, Error> {
        format::salt_from_blob(data)
    }

    pub fn derive_vault_key(
        data: &[u8],
        password: &SecretString,
    ) -> Result<SecretBox<Vec<u8>>, Error> {
        format::derive_key_from_password(data, password)
    }
}

fn parse_plaintext(decrypted: SecretBox<Vec<u8>>) -> Result<HashMap<String, SecretString>, Error> {
    let mut map = HashMap::new();
    let reader = Cursor::new(decrypted.expose_secret().as_slice());
    for item in dotenvy::from_read_iter(reader) {
        let (key, value) = item.map_err(|_| Error::InvalidEnv)?;
        map.insert(key, SecretString::new(value.into_boxed_str()));
    }
    Ok(map)
}

fn needs_quoting(value: &str) -> bool {
    value.is_empty()
        || value.contains('\n')
        || value.contains('\r')
        || value.contains('#')
        || value.contains('"')
        || value.contains('\\')
        || value.starts_with(' ')
        || value.ends_with(' ')
        || value.contains('\t')
}

fn escape_value(value: &str) -> String {
    if !needs_quoting(value) {
        return value.to_string();
    }
    let mut out = String::from('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn serialize_plaintext(vault: &EnvVault) -> SecretBox<Vec<u8>> {
    let mut keys: Vec<&String> = vault.0.keys().collect();
    keys.sort();

    let mut out = Vec::new();
    for key in keys {
        let value = vault.0.get(key).expect("key present");
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(escape_value(value.expose_secret()).as_bytes());
        out.push(b'\n');
    }
    SecretBox::new(Box::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn round_trip(values: &[(&str, &str)]) {
        let mut vault = EnvVault::new();
        for (k, v) in values {
            vault.set(*k, SecretString::new(Box::from(*v)));
        }
        let again = EnvVault::from_plaintext(serialize_plaintext(&vault)).unwrap();
        for (k, v) in values {
            assert_eq!(again.get(k).unwrap().expose_secret(), *v, "key={k}");
        }
    }

    #[test]
    fn parse_moves_values_into_secret_strings() {
        let plain = SecretBox::new(Box::new(b"API_KEY=secret\nDB_URL=postgres://x\n".to_vec()));
        let vault = EnvVault::from_plaintext(plain).unwrap();
        assert_eq!(vault.get("API_KEY").unwrap().expose_secret(), "secret");
        assert_eq!(vault.get("DB_URL").unwrap().expose_secret(), "postgres://x");
    }

    #[test]
    fn round_trip_simple() {
        round_trip(&[("FOO", "bar")]);
    }

    #[test]
    fn round_trip_special_characters() {
        round_trip(&[
            ("HASH", "hello # world"),
            ("QUOTED", "has \"quotes\""),
            ("MULTI", "line1\nline2"),
            ("SPACES", " leading and trailing "),
            ("BACKSLASH", "a\\b"),
            ("EMPTY", ""),
        ]);
    }

    #[test]
    fn round_trip_parsed_input() {
        let plain = SecretBox::new(Box::new(
            b"HASH=\"hello # world\"\nMULTI=\"a\\nb\"\n".to_vec(),
        ));
        let vault = EnvVault::from_plaintext(plain).unwrap();
        let again = EnvVault::from_plaintext(serialize_plaintext(&vault)).unwrap();
        assert_eq!(again.get("HASH").unwrap().expose_secret(), "hello # world");
        assert_eq!(again.get("MULTI").unwrap().expose_secret(), "a\nb");
    }
}
