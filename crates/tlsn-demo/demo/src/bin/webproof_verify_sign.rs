//! Verifier-side pipeline step: verify a persisted TLSNotary presentation
//! and, only on success, build and sign a canonical `ClaimV1`.
//!
//! Environment:
//! * `WEBPROOF_ARTIFACT_DIR` — directory written by `webproof-notarize`.
//! * `WEBPROOF_SIGNER_KEY` — Ed25519 seed (hex, base58 or JSON byte array).
//!   REQUIRED; never committed to the repository.
//! * `WEBPROOF_ALLOWED_HOSTS` — comma-separated exact hostnames the verifier
//!   is willing to sign claims about. REQUIRED.
//! * `WEBPROOF_TRUSTED_NOTARY_KEYS` — comma-separated hex notary verifying
//!   keys (defaults to the contents of `notary-key.hex` in the artifact dir;
//!   for the local in-process notary demo that file is trustworthy because
//!   prover and notary run in the same process).
//! * `CLAIM_TTL_SECONDS` — claim lifetime (default 300).
//!
//! Writes `signed-claim.json` to the artifact directory.

use std::path::PathBuf;
use webproof_tlsn_demo as common;

use anyhow::{bail, Context, Result};
use rand::RngCore;
use url::Url;
use webproof_tlsn::TlsnPresentationVerifier;
use webproof_verifier::ClaimSigner;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let dir = PathBuf::from(
        std::env::var("WEBPROOF_ARTIFACT_DIR").unwrap_or_else(|_| "artifacts/demo".into()),
    );
    let artifact = std::fs::read(dir.join("presentation.tlsn.bin"))
        .context("presentation.tlsn.bin not found; run webproof-notarize first")?;
    let request: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("request.json"))?)?;
    let expected_url = Url::parse(
        request
            .get("url")
            .and_then(|v| v.as_str())
            .context("request.json missing url")?,
    )?;
    let field = request
        .get("field")
        .and_then(|v| v.as_str())
        .context("request.json missing field")?
        .to_string();
    let fixture = request
        .get("fixture")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Host allowlist: exact, structured comparison against the expected URL.
    let allowed = std::env::var("WEBPROOF_ALLOWED_HOSTS")
        .context("WEBPROOF_ALLOWED_HOSTS must be set (comma-separated exact hostnames)")?;
    let expected_host = expected_url
        .host_str()
        .context("expected URL has no host")?;
    if !allowed
        .split(',')
        .map(str::trim)
        .any(|h| !h.is_empty() && h.eq_ignore_ascii_case(expected_host))
    {
        bail!("host {expected_host} is not in WEBPROOF_ALLOWED_HOSTS");
    }

    let trusted_notary_keys: Vec<Vec<u8>> = match std::env::var("WEBPROOF_TRUSTED_NOTARY_KEYS") {
        Ok(list) => list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(hex::decode)
            .collect::<Result<_, _>>()?,
        Err(_) => vec![hex::decode(
            std::fs::read_to_string(dir.join("notary-key.hex"))
                .context("notary-key.hex not found and WEBPROOF_TRUSTED_NOTARY_KEYS unset")?
                .trim(),
        )?],
    };

    let verifier = if fixture {
        TlsnPresentationVerifier::with_custom_roots(
            vec![tlsn_server_fixture_certs::CA_CERT_DER.to_vec()],
            trusted_notary_keys,
        )
    } else {
        TlsnPresentationVerifier::with_mozilla_roots(trusted_notary_keys)
    };

    let signer_key = std::env::var("WEBPROOF_SIGNER_KEY")
        .context("WEBPROOF_SIGNER_KEY must be set (Ed25519 seed)")?;
    let signer = ClaimSigner::new(common::parse_signing_key(&signer_key)?);

    let ttl: i64 = std::env::var("CLAIM_TTL_SECONDS")
        .unwrap_or_else(|_| "300".into())
        .trim()
        .parse()
        .context("CLAIM_TTL_SECONDS must be an integer")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    // The single gate: TLSNotary presentation verification happens inside
    // verify_and_sign; no claim is signed if it fails.
    let signed = signer
        .verify_and_sign(&verifier, &artifact, &expected_url, &field, now, ttl, nonce)
        .map_err(|e| anyhow::anyhow!("refusing to sign: {e}"))?;

    let out = dir.join("signed-claim.json");
    std::fs::write(&out, serde_json::to_string_pretty(&signed)?)?;

    println!("TLSNotary presentation verified.");
    println!(
        "Claim: {} = {}",
        signed.claim.claim_key, signed.claim.claim_value
    );
    println!("Source: {}", signed.claim.source_host);
    println!("Claim ID: {}", hex::encode(signed.claim_id));
    println!(
        "Verifier public key: {}",
        hex::encode(signed.verifier_public_key)
    );
    println!("Signed claim written to {}", out.display());
    Ok(())
}
