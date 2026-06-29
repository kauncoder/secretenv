use pem_rfc7468::LineEnding;
use secrecy::SecretBox;

use crate::constants::current_format;
use crate::error::Error;

pub const PEM_LABEL: &str = "SECRETENV KEY";
pub const PEM_BEGIN: &str = "-----BEGIN SECRETENV KEY-----";
pub const PEM_END: &str = "-----END SECRETENV KEY-----";

fn expected_key_len() -> Result<usize, Error> {
    current_format().key_len().ok_or(Error::EncryptionFailed)
}

pub fn export_keyfile(key: &[u8]) -> Vec<u8> {
    pem_rfc7468::encode_string(PEM_LABEL, LineEnding::LF, key)
        .expect("PEM encode with fixed label should not fail")
        .into_bytes()
}

pub fn import_keyfile(bytes: &[u8]) -> Result<SecretBox<Vec<u8>>, Error> {
    let key_len = expected_key_len()?;

    if bytes.len() == key_len {
        return Ok(SecretBox::new(Box::new(bytes.to_vec())));
    }

    let (label, key) = pem_rfc7468::decode_vec(bytes).map_err(|_| Error::InvalidKeyfile)?;
    if label != PEM_LABEL {
        return Err(Error::InvalidKeyfile);
    }
    if key.len() != key_len {
        return Err(Error::InvalidKeyfile);
    }
    Ok(SecretBox::new(Box::new(key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn pem_round_trip() {
        let key_len = expected_key_len().unwrap();
        let key = vec![0xABu8; key_len];
        let pem = export_keyfile(&key);
        let imported = import_keyfile(&pem).unwrap();
        assert_eq!(imported.expose_secret().as_slice(), key.as_slice());
    }

    #[test]
    fn pem_uses_rfc7468_line_wrapping() {
        let key_len = expected_key_len().unwrap();
        let pem = export_keyfile(&vec![0u8; key_len]);
        let text = std::str::from_utf8(&pem).unwrap();
        assert!(text.contains('\n'));
        assert!(text.starts_with(PEM_BEGIN));
        assert!(text.ends_with(&format!("{PEM_END}\n")));
    }

    #[test]
    fn raw_binary_import() {
        let key_len = expected_key_len().unwrap();
        let key = vec![0xCDu8; key_len];
        let imported = import_keyfile(&key).unwrap();
        assert_eq!(imported.expose_secret().as_slice(), key.as_slice());
    }

    #[test]
    fn rejects_wrong_pem_label() {
        let key_len = expected_key_len().unwrap();
        let pem =
            pem_rfc7468::encode_string("PRIVATE KEY", LineEnding::LF, &vec![0u8; key_len]).unwrap();
        assert!(matches!(
            import_keyfile(pem.as_bytes()),
            Err(Error::InvalidKeyfile)
        ));
    }
}
