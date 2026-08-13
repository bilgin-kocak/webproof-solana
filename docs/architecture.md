# Architecture

The TLSNotary adapter is an offchain cryptographic boundary. Its verified result enters `webproof-verifier`, which builds and signs the shared `webproof-core` claim. The TypeScript SDK submits native Ed25519 verification immediately before the Anchor instruction. The program parses all Ed25519 offsets and matches the key and complete message rather than checking only the program ID.

Artifacts stay offchain; `provenance_hash = SHA256(serialized TLSNotary presentation)` links the account to the presentation.
