//! In-process HTTPS test server, backed by the official
//! `tlsn-server-fixture` crate (axum over rustls, self-signed certificate
//! for `test-server.io`). Used by the local demo and tests so the complete
//! pipeline can run without any external network access.

use anyhow::Result;
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncWriteCompatExt;

pub use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

/// JSON endpoint served by the fixture.
pub const FIXTURE_JSON_PATH: &str = "/formats/json";

/// Starts the fixture on an ephemeral local port and returns the port.
/// Each accepted connection is served a single HTTP/1.1 exchange over TLS.
pub async fn start() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                if let Err(err) = tlsn_server_fixture::bind(socket.compat_write()).await {
                    tracing::debug!("fixture connection ended: {err}");
                }
            });
        }
    });
    Ok(port)
}
