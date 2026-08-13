# Architecture

```text
crates/tlsn-demo (Rust 1.95, pinned TLSNotary)          root workspace (Rust 1.85)
┌──────────────────────────────────────────┐   ┌─────────────────────────────────┐
│ webproof-notarize:                       │   │ webproof-core: ClaimV1, Borsh,  │
│   MPC-TLS prover + in-process notary     │   │   claim_id, domain separation   │
│   → presentation.tlsn.bin                │   │ webproof-verifier: signer seam  │
│ webproof-verify-sign:                    │──▶│   (TlsnProofVerifier trait,     │
│   TlsnPresentationVerifier               │   │   no signature w/o verification)│
│   (implements TlsnProofVerifier)         │   │ programs/webproof: Anchor       │
│   → signed-claim.json                    │   └─────────────────────────────────┘
└──────────────────────────────────────────┘
                     │ signed-claim.json
                     ▼
        sdk/typescript + cli:  [Ed25519 verify ix][submit_claim ix]  → Solana
```

The TLSNotary adapter is an offchain cryptographic boundary. Its verified
result enters `webproof-verifier`, which builds and signs the shared
`webproof-core` claim. The TypeScript SDK submits native Ed25519 verification
immediately before the Anchor instruction. The program parses all Ed25519
offsets and matches the key and complete message rather than checking only
the program ID.

The TLSNotary integration lives in a separate cargo workspace
(`crates/tlsn-demo`) because the pinned release requires Rust 1.95 while the
Anchor toolchain uses 1.85; the `TlsnProofVerifier` trait in
`webproof-verifier` is the seam between the two.

Artifacts stay offchain; `provenance_hash = SHA256(serialized TLSNotary
presentation)` links the account to the presentation.

## Disclosure policy (MVP)

The presentation reveals: the request line (including path), request headers
except `Authorization`/`Cookie`/`Proxy-Authorization` (revealed by name
only), and the entire response. The verifier requires the request line and
the full response to be covered by authenticated ranges before parsing.
Field-precise disclosure is a roadmap item: a partially-redacted body no
longer parses as JSON, so the MVP prefers working cryptographic provenance
over premature parsing complexity (as the specification allows).
