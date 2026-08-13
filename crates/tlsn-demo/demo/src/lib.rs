//! Shared configuration for the demo binaries.

use anyhow::{bail, Context, Result};
use url::Url;
use webproof_tlsn::{fixture, NotarizeConfig, ServerTrust};

/// Dev-only notary signing key seed, matching the upstream example. Override
/// with `WEBPROOF_NOTARY_KEY` (32-byte hex).
pub const DEV_NOTARY_KEY: [u8; 32] = [1u8; 32];

pub struct DemoTarget {
    /// URL the claim is expected to come from (https).
    pub url: Url,
    /// JSON pointer of the field to claim, e.g. `/meta/version`.
    pub field: String,
    /// Notarization config (server address may differ from the URL host when
    /// using the local fixture).
    pub notarize: NotarizeConfig,
    /// Whether the local fixture CA (rather than WebPKI) anchors the server
    /// certificate.
    pub fixture: bool,
}

/// Resolves the demo target from `DEMO_URL` / `DEMO_FIELD`.
///
/// Without `DEMO_URL`, an in-process HTTPS fixture (the official TLSNotary
/// test server) is started and notarized — this keeps the full pipeline
/// runnable with zero external network access. With `DEMO_URL`, the given
/// public HTTPS endpoint is notarized using the Mozilla WebPKI roots.
pub async fn resolve_target() -> Result<DemoTarget> {
    let notary_key = notary_key()?;
    let max_sent = env_usize("DEMO_MAX_SENT", webproof_tlsn::DEFAULT_MAX_SENT_DATA)?;
    let max_recv = env_usize("DEMO_MAX_RECV", webproof_tlsn::DEFAULT_MAX_RECV_DATA)?;

    match std::env::var("DEMO_URL") {
        Ok(raw) if !raw.trim().is_empty() => {
            let url = Url::parse(raw.trim()).context("DEMO_URL is not a valid URL")?;
            if url.scheme() != "https" {
                bail!("DEMO_URL must use https");
            }
            let host = url.host_str().context("DEMO_URL has no host")?.to_string();
            if url.username() != "" || url.password().is_some() {
                bail!("DEMO_URL must not contain credentials");
            }
            let port = url.port().unwrap_or(443);
            let mut uri = url.path().to_string();
            if let Some(query) = url.query() {
                uri.push('?');
                uri.push_str(query);
            }
            let field = std::env::var("DEMO_FIELD")
                .context("DEMO_FIELD must be set when DEMO_URL is used")?;
            Ok(DemoTarget {
                url,
                field: normalize_field(&field),
                notarize: NotarizeConfig {
                    server_addr: (host.clone(), port),
                    server_name: host,
                    uri,
                    extra_headers: Vec::new(),
                    server_trust: ServerTrust::Mozilla,
                    max_sent_data: max_sent,
                    max_recv_data: max_recv,
                    notary_key,
                },
                fixture: false,
            })
        }
        _ => {
            let port = fixture::start().await?;
            let field = std::env::var("DEMO_FIELD").unwrap_or_else(|_| "/meta/version".into());
            let url = Url::parse(&format!(
                "https://{}{}",
                fixture::SERVER_DOMAIN,
                fixture::FIXTURE_JSON_PATH
            ))?;
            Ok(DemoTarget {
                url,
                field: normalize_field(&field),
                notarize: NotarizeConfig {
                    server_addr: ("127.0.0.1".into(), port),
                    server_name: fixture::SERVER_DOMAIN.into(),
                    uri: fixture::FIXTURE_JSON_PATH.into(),
                    extra_headers: Vec::new(),
                    server_trust: ServerTrust::Custom(vec![fixture::CA_CERT_DER.to_vec()]),
                    max_sent_data: max_sent,
                    max_recv_data: max_recv,
                    notary_key,
                },
                fixture: true,
            })
        }
    }
}

/// Accepts either a JSON pointer (`/meta/version`) or a bare dotted key
/// (`price`, `meta.version`) and returns a JSON pointer.
pub fn normalize_field(field: &str) -> String {
    if field.starts_with('/') {
        field.to_string()
    } else {
        format!("/{}", field.replace('.', "/"))
    }
}

fn notary_key() -> Result<[u8; 32]> {
    match std::env::var("WEBPROOF_NOTARY_KEY") {
        Ok(raw) => {
            let bytes = hex::decode(raw.trim()).context("WEBPROOF_NOTARY_KEY must be hex")?;
            bytes
                .as_slice()
                .try_into()
                .ok()
                .context("WEBPROOF_NOTARY_KEY must be 32 bytes")
        }
        Err(_) => Ok(DEV_NOTARY_KEY),
    }
}

fn env_usize(name: &str, default: usize) -> Result<usize> {
    match std::env::var(name) {
        Ok(raw) => raw
            .trim()
            .parse()
            .with_context(|| format!("{name} must be an integer")),
        Err(_) => Ok(default),
    }
}

/// Parses `WEBPROOF_SIGNER_KEY` (32-byte Ed25519 seed) from hex, base58 or a
/// JSON byte array.
pub fn parse_signing_key(raw: &str) -> Result<ed25519_dalek::SigningKey> {
    let raw = raw.trim();
    let bytes: Vec<u8> = if raw.starts_with('[') {
        serde_json::from_str::<Vec<u8>>(raw).context("invalid JSON byte array")?
    } else if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(raw)?
    } else {
        bs58::decode(raw).into_vec().context("invalid base58")?
    };
    // Accept a 64-byte expanded keypair (Solana-style) by taking the seed.
    let seed: [u8; 32] = match bytes.len() {
        32 => bytes.as_slice().try_into().unwrap(),
        64 => bytes[..32].try_into().unwrap(),
        n => bail!("signing key must be 32 or 64 bytes, got {n}"),
    };
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}
