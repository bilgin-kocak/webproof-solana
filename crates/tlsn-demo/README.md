# TLSNotary integration workspace

This is a **separate cargo workspace** pinned to Rust 1.95.0 because the
pinned TLSNotary release requires it (see `../../docs/tlsnotary-version.md`);
the repository root workspace (Anchor) stays on 1.85.1 and excludes this
directory.

* `webproof-tlsn/` — library: real MPC-TLS notarization with an in-process
  notary (`notarize`), presentation building (`present`), and
  `TlsnPresentationVerifier`, the real implementation of
  `webproof_verifier::TlsnProofVerifier`. Only a presentation that passes
  TLSNotary cryptographic verification can produce `VerifiedTlsData`, and
  therefore a signed claim.
* `demo/` — binaries:
  * `spike` — Stage-1 acceptance check: notarize + present + verify against
    the official HTTPS test fixture (or `DEMO_URL`), print the verified host
    and field value.
  * `webproof-notarize` — persist a presentation artifact under
    `artifacts/`.
  * `webproof-verify-sign` — verify the artifact and sign a `ClaimV1`
    (requires `WEBPROOF_SIGNER_KEY` and `WEBPROOF_ALLOWED_HOSTS`).

Always build/run with `--release`: MPC-TLS is orders of magnitude slower
unoptimized. There is deliberately no fake HTTPS fallback anywhere; failures
abort before signing.
