# Security notes

* The signing capability must only receive the opaque `VerifiedTlsData` produced after TLSNotary verification.
* URLs must be HTTPS and hosts compared structurally and exactly against an allowlist. A service deployment must additionally resolve and reject loopback, RFC1918, link-local, metadata, and rebinding targets.
* JSON is parsed structurally and only scalar JSON Pointer values are accepted.
* Private signer/deployer keys and transcript artifacts are never committed.
* Signatures cover `WEBPROOF_SOLANA_CLAIM_V1 || borsh(ClaimV1)`; claim IDs cover only canonical Borsh bytes.
* Duplicate submission is rejected by Anchor's `init` of the deterministic claim PDA.
