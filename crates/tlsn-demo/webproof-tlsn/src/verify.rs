//! Verification of a persisted TLSNotary presentation artifact.
//!
//! [`TlsnPresentationVerifier`] implements the
//! [`webproof_verifier::TlsnProofVerifier`] trait. Only when
//! `Presentation::verify` succeeds — real TLSNotary cryptography: notary
//! signature, server identity proof, and transcript proofs — is
//! `VerifiedTlsData` constructed. Any failure means no data, and therefore
//! no signed claim.

use serde_json::Value;
use tlsn::{
    attestation::presentation::{Presentation, PresentationOutput},
    verifier::ServerCertVerifier,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_formats::http::{parse_request, parse_response};
use webproof_verifier::{TlsnProofVerifier, VerifiedTlsData};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("presentation artifact could not be deserialized")]
    Deserialize,
    #[error("presentation was signed by an untrusted notary key")]
    UntrustedNotary,
    #[error("TLSNotary presentation verification failed: {0}")]
    Verification(String),
    #[error("presentation does not prove the server identity")]
    MissingServerName,
    #[error("presentation does not include a transcript proof")]
    MissingTranscript,
    #[error("disclosed transcript does not cover the {0}")]
    Coverage(&'static str),
    #[error("failed to parse the disclosed HTTP data: {0}")]
    Http(String),
    #[error("disclosed response body is not valid JSON")]
    Json,
}

/// Verifies presentation artifacts produced by the pinned TLSNotary release.
pub struct TlsnPresentationVerifier {
    /// Trusted TLS root certificates (DER) for validating the server
    /// certificate chain inside the presentation.
    server_roots: Vec<Vec<u8>>,
    /// Allowlisted notary verifying keys (raw key bytes). The presentation
    /// must be signed by one of these keys.
    trusted_notary_keys: Vec<Vec<u8>>,
}

impl TlsnPresentationVerifier {
    /// Verifier trusting the Mozilla WebPKI roots for the server certificate.
    pub fn with_mozilla_roots(trusted_notary_keys: Vec<Vec<u8>>) -> Self {
        Self {
            server_roots: Vec::new(),
            trusted_notary_keys,
        }
    }

    /// Verifier trusting custom root certificates (used for the local test
    /// fixture).
    pub fn with_custom_roots(roots: Vec<Vec<u8>>, trusted_notary_keys: Vec<Vec<u8>>) -> Self {
        Self {
            server_roots: roots,
            trusted_notary_keys,
        }
    }

    fn crypto_provider(&self) -> Result<tlsn::attestation::CryptoProvider, VerifyError> {
        if self.server_roots.is_empty() {
            Ok(tlsn::attestation::CryptoProvider::default())
        } else {
            let root_store = RootCertStore {
                roots: self
                    .server_roots
                    .iter()
                    .cloned()
                    .map(CertificateDer)
                    .collect(),
            };
            Ok(tlsn::attestation::CryptoProvider {
                cert: ServerCertVerifier::new(&root_store)
                    .map_err(|e| VerifyError::Verification(e.to_string()))?,
                ..Default::default()
            })
        }
    }
}

impl TlsnProofVerifier for TlsnPresentationVerifier {
    type Error = VerifyError;

    fn verify(&self, artifact: &[u8]) -> Result<VerifiedTlsData, VerifyError> {
        let presentation: Presentation =
            bincode::deserialize(artifact).map_err(|_| VerifyError::Deserialize)?;

        // The notary key is the attestation trust anchor: reject anything not
        // signed by an allowlisted key before verifying.
        let key_data = &presentation.verifying_key().data;
        if !self
            .trusted_notary_keys
            .iter()
            .any(|trusted| trusted == key_data)
        {
            return Err(VerifyError::UntrustedNotary);
        }

        // Real TLSNotary cryptographic verification: notary signature over
        // the attestation, server certificate chain + identity proof, and
        // transcript (MAC) proofs for every disclosed byte.
        let PresentationOutput {
            server_name,
            transcript,
            ..
        } = presentation
            .verify(&self.crypto_provider()?)
            .map_err(|e| VerifyError::Verification(e.to_string()))?;

        let server_name = server_name.ok_or(VerifyError::MissingServerName)?;
        let tlsn::connection::ServerName::Dns(dns_name) = &server_name;
        let host = dns_name.as_str().to_string();
        let transcript = transcript.ok_or(VerifyError::MissingTranscript)?;

        // Parse the disclosed request and require the request line (method +
        // target) to be fully authenticated.
        let sent = transcript.sent_unsafe().to_vec();
        let request =
            parse_request(sent.as_slice()).map_err(|e| VerifyError::Http(e.to_string()))?;
        let request_line_indices = request.request.indices().clone();
        if !is_subset(&request_line_indices, transcript.sent_authed()) {
            return Err(VerifyError::Coverage("request line"));
        }
        let path = request.request.target.as_str().to_string();

        // Parse the disclosed response and require the entire response
        // (status line, headers, body) to be authenticated. This is the MVP
        // full-disclosure policy; a redacted body would not be parseable as
        // JSON anyway, and partially-authenticated bytes must never reach a
        // claim.
        let received = transcript.received_unsafe().to_vec();
        let response =
            parse_response(received.as_slice()).map_err(|e| VerifyError::Http(e.to_string()))?;
        let response_indices = response.indices().clone();
        if !is_subset(&response_indices, transcript.received_authed()) {
            return Err(VerifyError::Coverage("full response"));
        }
        let body = response
            .body
            .as_ref()
            .ok_or(VerifyError::Coverage("response body"))?;
        let body_bytes = body.content_data();
        let response_json: Value =
            serde_json::from_slice(&body_bytes).map_err(|_| VerifyError::Json)?;

        Ok(VerifiedTlsData::from_verified_presentation(
            host,
            path,
            response_json,
            artifact.to_vec(),
        ))
    }
}

fn is_subset(
    candidate: &tlsn::rangeset::set::RangeSet<usize>,
    authed: &tlsn::rangeset::set::RangeSet<usize>,
) -> bool {
    let mut remainder = candidate.clone();
    remainder.difference_mut(authed);
    remainder.is_empty()
}
