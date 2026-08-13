//! Prover-side pipeline step: notarize an HTTPS GET through TLSNotary and
//! persist the presentation artifact.
//!
//! Environment:
//! * `DEMO_URL` / `DEMO_FIELD` — target endpoint and JSON field (defaults to
//!   the in-process test fixture).
//! * `WEBPROOF_ARTIFACT_DIR` — output directory (default `artifacts/demo`).
//!
//! Outputs in the artifact directory:
//! * `presentation.tlsn.bin` — bincode-serialized TLSNotary presentation.
//! * `notary-key.hex` — the notary verifying key observed by the prover.
//! * `request.json` — the expected URL/field, passed to the verify step as
//!   *expectations* (never as trusted data).

use std::path::PathBuf;
use webproof_tlsn_demo as common;

use anyhow::Result;
use webproof_tlsn::{build_presentation, notarize};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let target = common::resolve_target().await?;
    let out_dir = PathBuf::from(
        std::env::var("WEBPROOF_ARTIFACT_DIR").unwrap_or_else(|_| "artifacts/demo".into()),
    );
    std::fs::create_dir_all(&out_dir)?;

    eprintln!(
        "Notarizing GET https://{}{} through TLSNotary (MPC-TLS)...",
        target.notarize.server_name, target.notarize.uri
    );
    let session = notarize(target.notarize.clone()).await?;
    let presentation = build_presentation(&session.attestation, &session.secrets)?;
    let artifact = bincode::serialize(&presentation)?;

    let presentation_path = out_dir.join("presentation.tlsn.bin");
    std::fs::write(&presentation_path, &artifact)?;
    std::fs::write(
        out_dir.join("notary-key.hex"),
        hex::encode(&session.notary_verifying_key),
    )?;
    std::fs::write(
        out_dir.join("request.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "url": target.url.as_str(),
            "field": target.field,
            "fixture": target.fixture,
        }))?,
    )?;

    println!("TLS session notarized.");
    println!("Presentation artifact: {}", presentation_path.display());
    println!(
        "Artifact SHA-256: {}",
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&artifact))
    );
    Ok(())
}
