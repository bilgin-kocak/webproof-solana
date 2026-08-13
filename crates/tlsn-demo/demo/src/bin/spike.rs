//! Stage 1 spike: proves that TLSNotary works end-to-end, independently of
//! any Solana code.
//!
//! Runs a real MPC-TLS session (prover + in-process notary) against an HTTPS
//! server, builds a selectively-disclosed presentation, verifies it with
//! TLSNotary's presentation verification, and prints the verified host and
//! field value.
//!
//! By default it targets an in-process instance of the official TLSNotary
//! HTTPS test fixture; set `DEMO_URL`/`DEMO_FIELD` to target a public API.

use anyhow::{Context, Result};
use webproof_tlsn::{build_presentation, notarize, TlsnPresentationVerifier};
use webproof_tlsn_demo as common;
use webproof_verifier::TlsnProofVerifier;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let target = common::resolve_target().await?;
    eprintln!(
        "Notarizing GET https://{}{} through TLSNotary (MPC-TLS)...",
        target.notarize.server_name, target.notarize.uri
    );

    let session = notarize(target.notarize.clone()).await?;
    eprintln!("MPC-TLS session complete; attestation received from notary.");

    let presentation = build_presentation(&session.attestation, &session.secrets)?;
    let artifact = bincode::serialize(&presentation)?;
    eprintln!(
        "Presentation built ({} bytes); verifying independently...",
        artifact.len()
    );

    let verifier = if target.fixture {
        TlsnPresentationVerifier::with_custom_roots(
            vec![webproof_tlsn::fixture::CA_CERT_DER.to_vec()],
            vec![session.notary_verifying_key.clone()],
        )
    } else {
        TlsnPresentationVerifier::with_mozilla_roots(vec![session.notary_verifying_key.clone()])
    };

    let verified = verifier
        .verify(&artifact)
        .map_err(|e| anyhow::anyhow!("presentation verification failed: {e}"))?;

    let value = verified
        .response()
        .pointer(&target.field)
        .with_context(|| format!("field {} not present in verified response", target.field))?
        .clone();

    println!("TLSNotary verification successful");
    println!();
    println!("Host:\n{}", verified.host());
    println!();
    println!("Field:\n{}", target.field);
    println!();
    println!("Value:\n{value}");

    Ok(())
}
