# Security notes

* The signing capability must only receive the opaque `VerifiedTlsData` produced after TLSNotary verification.
* URLs must be HTTPS and hosts compared structurally and exactly against an allowlist. A service deployment must additionally resolve and reject loopback, RFC1918, link-local, metadata, and rebinding targets.
* JSON is parsed structurally and only scalar JSON Pointer values are accepted.
* Private signer/deployer keys and transcript artifacts are never committed.
* Signatures cover `WEBPROOF_SOLANA_CLAIM_V1 || borsh(ClaimV1)`; claim IDs cover only canonical Borsh bytes.
* Duplicate submission is rejected by Anchor's `init` of the deterministic claim PDA.
* The verifier accepts only presentations signed by allowlisted notary keys. In the local demo the notary runs in-process (see `docs/trust-model.md`); the demo's notary dev key must never be trusted in a real deployment.
* The Ed25519 instruction is verified by full offset introspection: it must immediately precede `submit_claim`, contain exactly one signature, keep signature/key/message self-contained (all instruction indices pinned to `u16::MAX`), and byte-match the configured key and the complete domain-separated message.
* Only sanitized fixture-run artifacts are committed (`artifacts/example/`); generated presentations are gitignored because transcripts can contain sensitive response data.
