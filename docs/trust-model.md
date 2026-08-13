# Trust model

## What TLSNotary proves
TLSNotary cryptographically authenticates the relevant TLS server session and
the disclosed transcript data: the server certificate chain and identity, and
MAC-level proofs that the revealed bytes were exchanged in that session. It
does not establish that the application-level fact is truthful beyond what
that server returned.

## What the WebProof verifier does
The centralized verifier verifies the TLSNotary presentation
(`Presentation::verify` from the pinned official release: notary signature,
server identity proof, transcript proofs), requires the notary key to be
allowlisted, requires an exact HTTPS hostname match, structurally parses the
authenticated JSON scalar, normalizes `ClaimV1`, and signs the
domain-separated canonical Borsh bytes. Verification failure yields no
signature — the signing path is type-gated behind the verifier.

## What Solana verifies
The program requires the immediately preceding native Ed25519 instruction to
contain the configured key and the exact domain-separated submitted claim
(all offsets parsed; signature/key/message must be self-contained in that
instruction). It then enforces bounds, freshness, expiration, and an
immutable claim PDA.

## Current assumptions
This prototype is **not trustless**:

1. Solana trusts one configured verifier key to translate only successfully
   verified TLSNotary data. Compromise of that key or verifier can produce
   false claims.
2. In the local demo, the TLSNotary **notary runs in the same process as the
   prover** — the pattern used by the official example at the pinned release,
   which ships no standalone notary server. This demonstrates the protocol
   mechanics, but a prover colluding with (or operating) its notary can
   attest to fabricated sessions. A production deployment must use an
   independent notary trusted by the WebProof verifier; the verifier already
   enforces a notary-key allowlist in anticipation.

## Future trust minimization
Direct TLSNotary attestation verification, ZK proof of TLSNotary
verification, SP1/Groth16 wrappers, multiple independent attestors, threshold
signatures, or a decentralized verifier network. None of these are part of
this prototype.
