//! Builds a verifiable presentation from an attestation and secrets.
//!
//! Disclosure policy (MVP): reveal the request line (including the target
//! path), the `Host` header, all response headers, and the entire response
//! body. Sensitive request headers (`Authorization`, `Cookie`) are revealed
//! only by name, never by value.
//!
//! Field-precise JSON disclosure is supported by the pinned TLSNotary
//! release, but a partially-redacted body no longer parses as JSON on the
//! verifier side. The prototype therefore discloses the full response body,
//! as permitted by the specification; finer-grained disclosure is tracked as
//! a follow-up in the README roadmap.

use anyhow::Result;
use tlsn::attestation::{presentation::Presentation, Attestation, CryptoProvider, Secrets};
use tlsn_formats::http::HttpTranscript;

const SECRET_HEADERS: &[&str] = &["authorization", "cookie", "proxy-authorization"];

/// Builds a presentation disclosing the request structure and the complete
/// response.
pub fn build_presentation(attestation: &Attestation, secrets: &Secrets) -> Result<Presentation> {
    let transcript = HttpTranscript::parse(secrets.transcript())?;

    let mut builder = secrets.transcript_proof_builder();

    let request = &transcript.requests[0];
    // Request structure without headers/body, then the target path.
    builder.reveal_sent(request.without_data())?;
    builder.reveal_sent(&request.request.target)?;
    for header in &request.headers {
        let name = header.name.as_str().to_ascii_lowercase();
        if SECRET_HEADERS.contains(&name.as_str()) {
            builder.reveal_sent(header.without_value())?;
        } else {
            builder.reveal_sent(header)?;
        }
    }

    // The entire response: structure, headers and body.
    let response = &transcript.responses[0];
    builder.reveal_recv(response)?;

    let transcript_proof = builder.build()?;

    let provider = CryptoProvider::default();
    let mut builder = attestation.presentation_builder(&provider);
    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);

    Ok(builder.build()?)
}
