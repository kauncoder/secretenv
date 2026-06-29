/// Current format version written to new vault files.
pub const VERSION: u8 = 1;
pub const MAX_VAULT_FILE_BYTES: usize = 256 * 1024;

pub(crate) struct Argon2Params {
    pub(crate) m_cost: u32,
    pub(crate) t_cost: u32,
    pub(crate) p_cost: u32,
    pub(crate) output_len: Option<usize>,
}

/// Wire layout and crypto parameters for a fixed version.
pub(crate) struct FormatProfile {
    pub version: u8,
    version_len: usize,
    salt_len: usize,
    nonce_len: usize,
    aead_tag_len: usize,
    argon2: &'static Argon2Params,
}

impl FormatProfile {
    pub const fn version_offset(&self) -> usize {
        0
    }

    pub const fn salt_offset(&self) -> usize {
        self.version_len
    }

    pub const fn encrypted_payload_offset(&self) -> usize {
        self.salt_offset() + self.salt_len
    }

    pub const fn header_len(&self) -> usize {
        self.encrypted_payload_offset()
    }

    pub const fn min_encrypted_payload_len(&self) -> usize {
        self.nonce_len + self.aead_tag_len
    }

    pub const fn min_file_len(&self) -> usize {
        self.header_len() + self.min_encrypted_payload_len()
    }

    /// Total on-disk size for a vault blob encrypting `plaintext_len` bytes.
    pub const fn encrypted_blob_len(&self, plaintext_len: usize) -> usize {
        self.header_len() + self.min_encrypted_payload_len() + plaintext_len
    }

    pub const fn max_plaintext_bytes(&self, max_blob_bytes: usize) -> usize {
        max_blob_bytes.saturating_sub(self.header_len() + self.min_encrypted_payload_len())
    }

    pub const fn salt_len(&self) -> usize {
        self.salt_len
    }

    pub const fn nonce_len(&self) -> usize {
        self.nonce_len
    }

    pub const fn key_len(&self) -> Option<usize> {
        self.argon2.output_len
    }

    pub const fn argon2(&self) -> &'static Argon2Params {
        self.argon2
    }
}

const FORMAT_V1: FormatProfile = FormatProfile {
    version: 1,
    version_len: 1,
    salt_len: 16,
    nonce_len: 12,
    aead_tag_len: 16,
    argon2: &Argon2Params {
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
        output_len: Some(32),
    },
};

pub(crate) fn current_format() -> &'static FormatProfile {
    &FORMAT_V1
}

pub(crate) fn format_from_version(version: u8) -> Option<&'static FormatProfile> {
    match version {
        1 => Some(&FORMAT_V1),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_v1_layout() {
        let f = current_format();
        assert_eq!(f.version, 1);
        assert_eq!(f.salt_len(), 16);
        assert_eq!(f.header_len(), 17);
        assert_eq!(f.min_file_len(), 45);
        assert_eq!(f.encrypted_blob_len(100), 145);
        assert_eq!(
            f.max_plaintext_bytes(MAX_VAULT_FILE_BYTES),
            MAX_VAULT_FILE_BYTES - 45
        );
        assert_eq!(f.argon2().m_cost, 19_456);
        assert!(format_from_version(99).is_none());
    }
}
