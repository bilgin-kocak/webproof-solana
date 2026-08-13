# TLSNotary version pin

| | |
|---|---|
| Repository | https://github.com/tlsnotary/tlsn |
| Release tag | `v0.1.0-alpha.15` |
| Commit | `47aee45b53e06648c1b2ad3689b367b8c923fdec` (2026-05-21) |
| Reference example | `crates/examples/attestation/{prove,present,verify}.rs` at that tag |
| Rust toolchain (TLSN workspace) | 1.95.0 |

## How the pin is applied

The TLSNotary crates are **not published on crates.io** at this tag (they
depend on git-only revisions of `tlsnotary/tlsn-utils` and
`privacy-ethereum/mpz`), so `crates/tlsn-demo` declares them as git
dependencies pinned to the release commit:

```toml
tlsn = { git = "https://github.com/tlsnotary/tlsn", rev = "47aee45b53e06648c1b2ad3689b367b8c923fdec" }
```

A `Cargo.lock` is committed in `crates/tlsn-demo` so transitive versions are
reproducible.

## Important API/toolchain findings at this tag

* **MSRV**: `mpz-fields@0.1.0-alpha.6` declares `rust-version = 1.95`, newer
  than the Anchor workspace's toolchain. `crates/tlsn-demo` is therefore a
  separate cargo workspace with its own `rust-toolchain.toml` (1.95.0); the
  root workspace (Anchor 0.31.1) is excluded from it and stays on 1.85.1.
* **No notary-server / notary-client crates** exist at this tag. The official
  attestation example runs the notary **in-process** over
  `tokio::io::duplex`, and this repository follows that pattern (see
  `docs/trust-model.md` for what that means for trust).
* The attestation flow (`Session` → `Prover::commit/connect/prove` →
  `AttestationRequest` → notary builds `Attestation` → `Secrets` →
  `Presentation`) replaced the older `Prover::notarize` APIs that most
  tutorials still describe. Presentations/attestations are persisted with
  `bincode` 1.3, exactly as in the upstream example.
* **TLS 1.2 only**: the only certificate-binding variant at this tag is
  `CertBinding::V1_2`; TLS-1.3-only servers cannot be notarized.
* Responses must be uncompressed (`Accept-Encoding: identity`).
* MPC-TLS is far too slow in unoptimized builds; run with `--release` (the
  tlsn-demo workspace also sets `opt-level = 3` for dependencies in dev).

## Acceptance evidence

`cargo run --release --bin spike` inside `crates/tlsn-demo` performs a real
MPC-TLS session (prover + in-process notary) against the official
`tlsn-server-fixture` HTTPS server, builds a selectively-disclosed
presentation, verifies it with `Presentation::verify`, and prints the
cryptographically verified host and JSON field value. No mock or plain-HTTPS
fallback exists anywhere in the pipeline; a failed verification aborts before
any claim is signed.
