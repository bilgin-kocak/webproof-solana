# Trust model

## What TLSNotary proves
TLSNotary cryptographically authenticates the relevant TLS server session and the disclosed transcript data. It does not establish that the application-level fact is truthful beyond what that server returned.

## What the WebProof verifier does
The centralized verifier verifies the TLSNotary presentation, requires an exact HTTPS hostname, structurally parses the authenticated JSON scalar, normalizes `ClaimV1`, and signs the domain-separated canonical Borsh bytes. Verification failure yields no signature.

## What Solana verifies
The program requires the immediately preceding native Ed25519 instruction to contain the configured key and the exact domain-separated submitted claim. It then enforces bounds, freshness, expiration, and an immutable claim PDA.

## Current assumption
This prototype is **not trustless**. Solana trusts one configured verifier to translate only successfully verified TLSNotary data. Compromise of that key or verifier can produce false claims.

Future minimization may use direct TLSNotary attestation verification, a ZK/SP1/Groth16 wrapper, multiple attestors, threshold signatures, or a decentralized verifier network.
