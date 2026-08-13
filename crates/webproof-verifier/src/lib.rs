use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use webproof_core::{ClaimError, ClaimV1, VERSION};

/// Output from the TLSNotary verification boundary. Construction is private:
/// callers cannot reach signing without a successful proof verifier.
#[derive(Debug)]
pub struct VerifiedTlsData {
    host: String,
    path: String,
    response: Value,
    artifact: Vec<u8>,
}

pub trait TlsnProofVerifier {
    type Error;
    fn verify(&self, artifact: &[u8]) -> Result<VerifiedTlsData, Self::Error>;
}

impl VerifiedTlsData {
    /// Adapter used only by a real TLSNotary integration after its presentation
    /// has cryptographically verified. Keeping this crate independent of the
    /// fast-moving TLSN API makes the security boundary explicit.
    pub fn from_verified_presentation(
        host: String,
        path: String,
        response: Value,
        artifact: Vec<u8>,
    ) -> Self {
        Self {
            host,
            path,
            response,
            artifact,
        }
    }

    /// Verified TLS server identity (from the certificate chain).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Disclosed request path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Disclosed, authenticated response body.
    pub fn response(&self) -> &Value {
        &self.response
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TLSNotary verification failed")]
    Tlsn,
    #[error("source host does not exactly match the allowlist")]
    Host,
    #[error("requested JSON field is absent or is not a scalar")]
    Field,
    #[error(transparent)]
    Claim(#[from] ClaimError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedClaim {
    pub claim: ClaimV1,
    pub claim_id: [u8; 32],
    pub signature: Vec<u8>,
    pub verifier_public_key: [u8; 32],
    pub tlsn_artifact_hash: [u8; 32],
}

pub struct ClaimSigner {
    key: SigningKey,
}
impl ClaimSigner {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }
    pub fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_sign<V: TlsnProofVerifier>(
        &self,
        verifier: &V,
        artifact: &[u8],
        expected_url: &Url,
        field: &str,
        now: i64,
        ttl: i64,
        nonce: [u8; 32],
    ) -> Result<SignedClaim, Error> {
        let verified = verifier.verify(artifact).map_err(|_| Error::Tlsn)?;
        self.sign_verified(verified, expected_url, field, now, ttl, nonce)
    }

    fn sign_verified(
        &self,
        data: VerifiedTlsData,
        expected_url: &Url,
        field: &str,
        now: i64,
        ttl: i64,
        nonce: [u8; 32],
    ) -> Result<SignedClaim, Error> {
        if expected_url.scheme() != "https" || expected_url.host_str() != Some(data.host.as_str()) {
            return Err(Error::Host);
        }
        let value = data.response.pointer(field).ok_or(Error::Field)?;
        let value = match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => "null".into(),
            _ => return Err(Error::Field),
        };
        let provenance_hash: [u8; 32] = Sha256::digest(&data.artifact).into();
        let claim = ClaimV1 {
            version: VERSION,
            source_host: data.host,
            request_path_hash: Sha256::digest(data.path.as_bytes()).into(),
            claim_key: field.into(),
            claim_value: value,
            issued_at: now,
            expires_at: now.saturating_add(ttl),
            nonce,
            provenance_hash,
        };
        claim.validate(now, ttl)?;
        let signature: Signature = self.key.sign(&claim.signing_message());
        Ok(SignedClaim {
            claim_id: claim.claim_id(),
            signature: signature.to_bytes().to_vec(),
            verifier_public_key: self.public_key().to_bytes(),
            tlsn_artifact_hash: provenance_hash,
            claim,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Mock(bool);
    impl TlsnProofVerifier for Mock {
        type Error = ();
        fn verify(&self, a: &[u8]) -> Result<VerifiedTlsData, ()> {
            if !self.0 {
                return Err(());
            }
            Ok(VerifiedTlsData::from_verified_presentation(
                "api.example.com".into(),
                "/data".into(),
                serde_json::json!({"price":"12.34"}),
                a.into(),
            ))
        }
    }
    fn signer() -> ClaimSigner {
        ClaimSigner::new(SigningKey::from_bytes(&[7; 32]))
    }
    #[test]
    fn verified_proof_can_be_signed() {
        let s = signer();
        let out = s
            .verify_and_sign(
                &Mock(true),
                b"proof",
                &Url::parse("https://api.example.com/data").unwrap(),
                "/price",
                100,
                300,
                [9; 32],
            )
            .unwrap();
        use ed25519_dalek::Verifier;
        assert!(s
            .public_key()
            .verify(
                &out.claim.signing_message(),
                &Signature::from_slice(&out.signature).unwrap()
            )
            .is_ok());
    }
    #[test]
    fn failed_proof_produces_no_signature() {
        assert!(matches!(
            signer().verify_and_sign(
                &Mock(false),
                b"bad",
                &Url::parse("https://api.example.com/data").unwrap(),
                "/price",
                100,
                300,
                [9; 32]
            ),
            Err(Error::Tlsn)
        ));
    }
    #[test]
    fn non_https_expected_url_fails() {
        assert!(matches!(
            signer().verify_and_sign(
                &Mock(true),
                b"p",
                &Url::parse("http://api.example.com/data").unwrap(),
                "/price",
                100,
                300,
                [0; 32]
            ),
            Err(Error::Host)
        ));
    }
    #[test]
    fn any_modified_claim_field_breaks_the_signature() {
        use ed25519_dalek::Verifier;
        let s = signer();
        let out = s
            .verify_and_sign(
                &Mock(true),
                b"proof",
                &Url::parse("https://api.example.com/data").unwrap(),
                "/price",
                100,
                300,
                [9; 32],
            )
            .unwrap();
        let sig = Signature::from_slice(&out.signature).unwrap();
        let verify = |c: &ClaimV1| s.public_key().verify(&c.signing_message(), &sig).is_ok();
        assert!(verify(&out.claim));
        let mutations: Vec<Box<dyn Fn(&mut ClaimV1)>> = vec![
            Box::new(|c| c.source_host = "api.evil.com".into()),
            Box::new(|c| c.claim_key = "/other".into()),
            Box::new(|c| c.claim_value = "99.99".into()),
            Box::new(|c| c.issued_at += 1),
            Box::new(|c| c.expires_at += 1),
            Box::new(|c| c.nonce = [0xAA; 32]),
            Box::new(|c| c.provenance_hash = [0xBB; 32]),
            Box::new(|c| c.version = 2),
        ];
        for mutate in mutations {
            let mut modified = out.claim.clone();
            mutate(&mut modified);
            assert!(!verify(&modified), "mutation should invalidate signature");
        }
    }
    #[test]
    fn deceptive_host_and_missing_field_fail() {
        let s = signer();
        assert!(matches!(
            s.verify_and_sign(
                &Mock(true),
                b"p",
                &Url::parse("https://api.example.com.attacker.com/data").unwrap(),
                "/price",
                100,
                300,
                [0; 32]
            ),
            Err(Error::Host)
        ));
        assert!(matches!(
            s.verify_and_sign(
                &Mock(true),
                b"p",
                &Url::parse("https://api.example.com/data").unwrap(),
                "/missing",
                100,
                300,
                [0; 32]
            ),
            Err(Error::Field)
        ));
    }
}
