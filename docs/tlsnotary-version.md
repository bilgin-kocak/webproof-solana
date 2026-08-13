# TLSNotary dependency record

## Research status (12 August 2026)

The implementation environment could not access either `docs.tlsnotary.org` or GitHub (the documentation request returned HTTP 401 and GitHub's CONNECT tunnel returned 403). Consequently this repository **does not claim a TLSNotary version or API that could not be verified**. The TLSNotary spike is intentionally not represented as complete and ordinary HTTPS is not substituted.

Before enabling the spike, verify the current official `tlsn` repository's `tlsn/examples` prover/verifier presentation example, record its release tag and commit here, and pin that commit in `crates/tlsn-demo/Cargo.toml`. This is a release blocker. The stable Rust/Node pins elsewhere are Rust 1.85.1, Anchor 0.31.1, and pnpm 10.28.1.

## Required spike acceptance check

The spike must run a notary, create a real MPC-TLS presentation, verify the server identity and disclosed response bytes using official APIs, and only then construct `VerifiedTlsData::from_verified_presentation`. A normal HTTP client, self-signed fixture, or hash of an unverified response does not satisfy this check.
