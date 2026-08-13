//! MPC-TLS notarization of a single HTTPS GET request.
//!
//! Ported from the official TLSNotary `attestation/prove.rs` example at the
//! pinned release. The notary runs in-process over an in-memory duplex
//! stream, exactly as in the upstream example.

use std::future::IntoFuture;

use anyhow::{Context, Result};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use tlsn::{
    attestation::{
        request::{Request as AttestationRequest, RequestConfig},
        signing::Secp256k1Signer,
        Attestation, AttestationConfig, CryptoProvider, Secrets,
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::{CertBinding, ConnectionInfo, HandshakeData, ServerName, TranscriptLength},
    prover::ProverOutput,
    transcript::{ContentType, TranscriptCommitConfig},
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
    Session,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};

const USER_AGENT: &str = "webproof-tlsn/0.1";

/// How the TLS server certificate chain is validated during notarization.
#[derive(Clone, Debug)]
pub enum ServerTrust {
    /// Mozilla WebPKI roots — use for real public HTTPS endpoints.
    Mozilla,
    /// Custom root certificates (DER) — used for the local test fixture.
    Custom(Vec<Vec<u8>>),
}

impl ServerTrust {
    fn root_store(&self) -> RootCertStore {
        match self {
            ServerTrust::Mozilla => RootCertStore::mozilla(),
            ServerTrust::Custom(roots) => RootCertStore {
                roots: roots.iter().cloned().map(CertificateDer).collect(),
            },
        }
    }
}

/// Configuration for one notarized HTTPS GET request.
#[derive(Clone, Debug)]
pub struct NotarizeConfig {
    /// TCP address to connect to, e.g. `("api.example.com", 443)` or a local
    /// fixture address.
    pub server_addr: (String, u16),
    /// TLS server name (SNI / certificate identity), e.g. `api.example.com`.
    pub server_name: String,
    /// Request target, e.g. `/v2/prices/BTC-USD/spot`.
    pub uri: String,
    /// Extra request headers.
    pub extra_headers: Vec<(String, String)>,
    /// Server certificate trust configuration.
    pub server_trust: ServerTrust,
    /// Maximum bytes sent (must cover the request).
    pub max_sent_data: usize,
    /// Maximum bytes received (must cover the full response).
    pub max_recv_data: usize,
    /// secp256k1 signing key seed for the in-process notary. Dev-only.
    pub notary_key: [u8; 32],
}

/// Output of a successful notarization.
pub struct NotarizedSession {
    pub attestation: Attestation,
    pub secrets: Secrets,
    /// The notary's verifying key, as (algorithm id, key bytes) — the
    /// verifier side must decide whether it trusts this key.
    pub notary_verifying_key: Vec<u8>,
}

/// Upper bound for one notarization. The MPC protocol normally completes in
/// seconds (release builds); the timeout converts rare scheduler deadlocks
/// under constrained CPU into a retryable error instead of a hang.
pub const NOTARIZE_TIMEOUT_SECS: u64 = 120;

/// Runs a real MPC-TLS session with an in-process notary and returns the
/// attestation and secrets.
pub async fn notarize(config: NotarizeConfig) -> Result<NotarizedSession> {
    tokio::time::timeout(
        std::time::Duration::from_secs(NOTARIZE_TIMEOUT_SECS),
        notarize_inner(config),
    )
    .await
    .context("notarization timed out")?
}

async fn notarize_inner(config: NotarizeConfig) -> Result<NotarizedSession> {
    let (notary_socket, prover_socket) = tokio::io::duplex(1 << 23);

    let notary_config = config.clone();
    let notary_task = tokio::spawn(async move { notary(notary_socket, notary_config).await });

    let output = prover(prover_socket, &config).await?;
    notary_task
        .await
        .context("notary task panicked")?
        .context("notary failed")?;

    Ok(output)
}

async fn prover<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    config: &NotarizeConfig,
) -> Result<NotarizedSession> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(config.max_sent_data)
                .max_recv_data(config.max_recv_data)
                .build()?,
        )
        .await?;

    let client_socket =
        tokio::net::TcpStream::connect((config.server_addr.0.as_str(), config.server_addr.1))
            .await
            .context("failed to reach the HTTPS server")?;

    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(config.server_name.as_str().try_into()?))
            .root_store(config.server_trust.root_store())
            .build()?,
        client_socket.compat(),
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());

    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let mut request_builder = Request::builder()
        .uri(&config.uri)
        .header("Host", &config.server_name)
        .header("Accept", "*/*")
        // TLSNotary tooling does not support compressed responses.
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT);
    for (key, value) in &config.extra_headers {
        request_builder = request_builder.header(key.as_str(), value.as_str());
    }
    let request = request_builder.body(Empty::<Bytes>::new())?;

    debug!("sending request through MPC-TLS");
    let response = request_sender.send_request(request).await?;
    anyhow::ensure!(
        response.status() == StatusCode::OK,
        "server returned status {}",
        response.status()
    );

    let mut prover = prover_task.await??;

    // Commit to the transcript (request/response structure and every JSON
    // value in the response body, via the default HTTP commit strategy).
    let transcript = HttpTranscript::parse(prover.transcript())?;
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;
    let transcript_commit = builder.build()?;

    let mut builder = RequestConfig::builder();
    builder.transcript_commit(transcript_commit);
    let request_config = builder.build()?;

    let mut builder = ProveConfig::builder(prover.transcript());
    if let Some(commit_config) = request_config.transcript_commit() {
        builder.transcript_commit(commit_config.clone());
    }
    let disclosure_config = builder.build()?;

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&disclosure_config).await?;

    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    let mut builder = AttestationRequest::builder(&request_config);
    builder
        .server_name(ServerName::Dns(config.server_name.as_str().try_into()?))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .context("server certificate chain missing")?
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .context("server signature missing")?
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);

    let (request, secrets) = builder.build(&CryptoProvider::default())?;

    // Reclaim the socket and exchange the attestation request/response with
    // the in-process notary over the wire, as in the upstream example.
    handle.close();
    let mut socket = driver_task.await??;

    let request_bytes = bincode::serialize(&request)?;
    socket.write_all(&request_bytes).await?;
    socket.close().await?;

    let mut attestation_bytes = Vec::new();
    socket.read_to_end(&mut attestation_bytes).await?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes)?;

    // Check the attestation is consistent with the prover's view.
    let provider = CryptoProvider::default();
    request.validate(&attestation, &provider)?;

    let notary_verifying_key = attestation.body.verifying_key().data.clone();

    Ok(NotarizedSession {
        attestation,
        secrets,
        notary_verifying_key,
    })
}

async fn notary<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    config: NotarizeConfig,
) -> Result<()> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier_config = VerifierConfig::builder()
        .root_store(config.server_trust.root_store())
        .build()?;

    let verifier = match handle.new_verifier(verifier_config)?.commit().await? {
        VerifierCommitStart::Mpc(verifier) => verifier.accept().await?.run().await?,
        VerifierCommitStart::Proxy(verifier) => {
            verifier.reject(Some("expecting to use MPC-TLS")).await?;
            anyhow::bail!("proxy mode rejected: this notary only supports MPC-TLS");
        }
    };

    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;

    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    let sent_len = tls_transcript
        .sent()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();
    let recv_len = tls_transcript
        .recv()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    handle.close();
    let mut socket = driver_task.await??;

    let mut request_bytes = Vec::new();
    socket.read_to_end(&mut request_bytes).await?;
    let request: AttestationRequest = bincode::deserialize(&request_bytes)?;

    let signing_key = k256::ecdsa::SigningKey::from_bytes(&config.notary_key.into())?;
    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let att_config = att_config_builder.build()?;

    let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
        anyhow::bail!("unsupported certificate binding version");
    };

    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments);

    let attestation = builder.build(&provider)?;

    let attestation_bytes = bincode::serialize(&attestation)?;
    socket.write_all(&attestation_bytes).await?;
    socket.close().await?;

    Ok(())
}
