use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERSION: u8 = 1;
pub const DOMAIN_SEPARATOR: &[u8] = b"WEBPROOF_SOLANA_CLAIM_V1";
pub const MAX_SOURCE_HOST: usize = 128;
pub const MAX_CLAIM_KEY: usize = 128;
pub const MAX_CLAIM_VALUE: usize = 256;
pub const MAX_FUTURE_SKEW_SECONDS: i64 = 30;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ClaimV1 {
    pub version: u8,
    pub source_host: String,
    pub request_path_hash: [u8; 32],
    pub claim_key: String,
    pub claim_value: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: [u8; 32],
    pub provenance_hash: [u8; 32],
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ClaimError {
    #[error("unsupported claim version")]
    Version,
    #[error("field {0} is empty or exceeds its byte limit")]
    Length(&'static str),
    #[error("claim expiration must be after issuance")]
    TimeWindow,
    #[error("claim is expired")]
    Expired,
    #[error("claim was issued too far in the future")]
    Future,
    #[error("claim exceeds maximum age")]
    TooOld,
}

impl ClaimV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("serialization of ClaimV1 is infallible")
    }

    pub fn claim_id(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    pub fn signing_message(&self) -> Vec<u8> {
        let bytes = self.canonical_bytes();
        let mut message = Vec::with_capacity(DOMAIN_SEPARATOR.len() + bytes.len());
        message.extend_from_slice(DOMAIN_SEPARATOR);
        message.extend_from_slice(&bytes);
        message
    }

    pub fn validate(&self, now: i64, max_age: i64) -> Result<(), ClaimError> {
        if self.version != VERSION {
            return Err(ClaimError::Version);
        }
        bounded(&self.source_host, MAX_SOURCE_HOST, "source_host")?;
        bounded(&self.claim_key, MAX_CLAIM_KEY, "claim_key")?;
        bounded(&self.claim_value, MAX_CLAIM_VALUE, "claim_value")?;
        if self.expires_at <= self.issued_at {
            return Err(ClaimError::TimeWindow);
        }
        if now > self.expires_at {
            return Err(ClaimError::Expired);
        }
        if self.issued_at > now.saturating_add(MAX_FUTURE_SKEW_SECONDS) {
            return Err(ClaimError::Future);
        }
        if now.saturating_sub(self.issued_at) > max_age {
            return Err(ClaimError::TooOld);
        }
        Ok(())
    }
}

fn bounded(value: &str, max: usize, name: &'static str) -> Result<(), ClaimError> {
    if value.is_empty() || value.len() > max {
        Err(ClaimError::Length(name))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn claim() -> ClaimV1 {
        ClaimV1 {
            version: 1,
            source_host: "api.example.com".into(),
            request_path_hash: [1; 32],
            claim_key: "price".into(),
            claim_value: "12345.67".into(),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_300,
            nonce: [2; 32],
            provenance_hash: [3; 32],
        }
    }
    #[test]
    fn hash_is_sha256_of_borsh() {
        let c = claim();
        assert_eq!(c.claim_id(), Sha256::digest(c.canonical_bytes()).as_slice());
    }
    #[test]
    fn validates_bounds_and_time() {
        assert!(claim().validate(1_700_000_010, 300).is_ok());
        let mut c = claim();
        c.claim_value = "x".repeat(257);
        assert_eq!(
            c.validate(1_700_000_010, 300),
            Err(ClaimError::Length("claim_value"))
        );
    }
    #[test]
    fn rejects_expired_future_and_bad_window() {
        let mut c = claim();
        assert_eq!(c.validate(1_700_000_301, 400), Err(ClaimError::Expired));
        c = claim();
        c.issued_at = 1_700_000_100;
        c.expires_at = 1_700_000_400;
        assert_eq!(c.validate(1_700_000_000, 400), Err(ClaimError::Future));
        c = claim();
        c.expires_at = c.issued_at;
        assert_eq!(c.validate(1_700_000_000, 400), Err(ClaimError::TimeWindow));
    }
    #[test]
    fn matches_repository_golden_vector() {
        // Keep the checked-in vector text-only so it can be reviewed by PR
        // tooling that does not render binary files.
        let expected = include_str!("../../../test-vectors/claim-v1.hex").trim();
        assert_eq!(hex::encode(claim().canonical_bytes()), expected);
        assert_eq!(
            hex::encode(claim().claim_id()),
            "6a32a1a241721185d051f0c694ed0ee20f1b36307dd853b5557735708b5e487d"
        );
    }
}
