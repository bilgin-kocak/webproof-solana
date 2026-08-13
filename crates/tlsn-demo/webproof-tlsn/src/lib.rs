//! Real TLSNotary integration for WebProof.
//!
//! This crate wires the official TLSNotary release (pinned in
//! `docs/tlsnotary-version.md`) into the `webproof-verifier` security seam:
//!
//! * [`notarize`] runs a genuine MPC-TLS session against an HTTPS server and
//!   produces an attestation plus the prover's secrets. The notary runs
//!   in-process (the pattern used by the official `attestation` example);
//!   this trust caveat is documented in `docs/trust-model.md`.
//! * [`present`] builds a verifiable, selectively-disclosed presentation
//!   artifact from the attestation.
//! * [`verify`] implements [`webproof_verifier::TlsnProofVerifier`] over a
//!   persisted presentation artifact. Only a presentation that passes real
//!   TLSNotary cryptographic verification yields `VerifiedTlsData`, which is
//!   the sole path to a signed claim.

pub mod notarize;
pub mod present;
pub mod verify;

#[cfg(feature = "fixture")]
pub mod fixture;

pub use notarize::{notarize, NotarizeConfig, NotarizedSession, ServerTrust};
pub use present::build_presentation;
pub use verify::{TlsnPresentationVerifier, VerifyError};

/// Maximum bytes sent to the server (preprocessed before the connection).
pub const DEFAULT_MAX_SENT_DATA: usize = 1 << 12;
/// Maximum bytes received from the server.
pub const DEFAULT_MAX_RECV_DATA: usize = 1 << 14;
