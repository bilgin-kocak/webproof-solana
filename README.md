# WebProof

**Verifiable HTTPS data for Solana using TLSNotary.**

Solana programs cannot directly query Web2 HTTPS APIs. WebProof allows an
offchain TLSNotary session to authenticate data returned by an HTTPS server
and makes the resulting claim usable by Solana programs.

```text
HTTPS API
    ↓  TLS (MPC-TLS, notarized)
TLSNotary
    ↓  verified presentation
WebProof Verifier
    ↓  signed canonical ClaimV1
Solana (native Ed25519 verify + webproof program)
    ↓
VerifiedClaim account (PDA)
```

## Why WebProof?

A normal Web2 provider does not need to add a blockchain integration for its
data to become usable onchain. TLSNotary cryptographically authenticates what
an HTTPS server actually returned; WebProof turns that into a compact signed
claim a Solana program can verify with one native instruction.

> Price data is used only as a simple demonstration of authenticated HTTPS
> provenance. WebProof is intended primarily for Web2 data for which
> dedicated blockchain oracle infrastructure does not exist.

## Demo

```bash
pnpm install
pnpm demo:local
```

`pnpm demo:local` runs the complete pipeline with **zero external
dependencies**: it performs a real MPC-TLS notarization (prover + in-process
notary, per the official TLSNotary example) against the official TLSNotary
HTTPS test fixture, builds and cryptographically verifies a
selectively-disclosed presentation, signs a canonical claim, starts
`solana-test-validator`, submits the claim with a native Ed25519 verification
instruction, and asserts the stored account matches the authenticated data:

```text
[1/5] Requesting HTTPS data through TLSNotary...
✓ TLS session authenticated
[2/5] Verifying transcript...
[3/5] Creating WebProof claim...
[4/5] Signing claim...
✓ Source authenticated
✓ /meta/version = 1.2
✓ Claim signed
[5/5] Submitting to Solana...
✓ Signature verified onchain
✓ Claim stored

Transaction: <signature>
Claim PDA:   <address>
```

To prove a field from a real public API instead (requires normal internet
egress):

```bash
DEMO_URL="https://api.coinbase.com/v2/prices/BTC-USD/spot" \
DEMO_FIELD="/data/amount" \
pnpm demo:local
```

Individual steps are available via the CLI: `pnpm webproof prove | verify |
init | submit | get | demo`.

## Architecture

1. The pinned official TLSNotary prover performs the HTTPS GET inside
   MPC-TLS; a notary attests to the session (`crates/tlsn-demo`).
2. A selectively-disclosed presentation is built: request line + Host header
   + full response; secret request headers stay hidden.
3. The WebProof verifier (`crates/webproof-verifier` +
   `crates/tlsn-demo/webproof-tlsn`) cryptographically verifies the
   presentation, requires an exact hostname match against an allowlist, and
   structurally parses one scalar JSON field.
4. It builds a bounded canonical `ClaimV1` (`crates/webproof-core`) with
   `provenance_hash = SHA256(presentation artifact)` and signs
   `WEBPROOF_SOLANA_CLAIM_V1 || borsh(claim)` with Ed25519.
5. The TypeScript SDK (`sdk/typescript`) submits one transaction: a native
   Ed25519 verification instruction immediately followed by `submit_claim`.
6. The Anchor program (`programs/webproof`) parses the Ed25519 instruction's
   offsets, byte-compares the configured verifier key and the exact
   domain-separated message, validates version/bounds/freshness, and creates
   the immutable `PDA(["claim", claim_id])`.

See [architecture](docs/architecture.md), [trust model](docs/trust-model.md),
[security notes](docs/security.md), and the
[TLSNotary version pin](docs/tlsnotary-version.md).

## Quick Start

```bash
# Rust unit + golden-vector tests (root workspace, Rust 1.85.1)
cargo test --workspace

# TLSNotary pipeline tests + spike (separate workspace, Rust 1.95.0 — see docs/tlsnotary-version.md)
cd crates/tlsn-demo
cargo run --release --bin spike          # real MPC-TLS against the local fixture
cargo test --release --features fixture  # pipeline + tamper tests
cd ../..

# TypeScript
pnpm install && pnpm build && pnpm test

# Onchain test matrix (starts its own validator)
anchor test

# Full local E2E
pnpm demo:local
```

## How It Works

TLSNotary's MPC-TLS protocol lets a prover convince a verifier (notary) of
what an HTTPS server sent without the server participating. The notary signs
an attestation over transcript commitments; the prover derives a
*presentation* that selectively reveals transcript bytes. WebProof verifies
that presentation offchain, then bridges it to Solana with a plain Ed25519
signature over a canonical claim — which Solana can verify natively. The
program never runs TLS; it verifies that the *configured verifier* signed the
*exact* submitted claim (full offset introspection of the Ed25519
instruction, not just "an Ed25519 instruction exists").

## Claim Format

`ClaimV1` (canonical encoding: Borsh):

| field | type | notes |
|---|---|---|
| `version` | `u8` | must be 1 |
| `source_host` | `String` | verified TLS identity, ≤128 bytes |
| `request_path_hash` | `[u8;32]` | SHA-256 of the disclosed request path |
| `claim_key` | `String` | JSON pointer of the field, ≤128 bytes |
| `claim_value` | `String` | canonical scalar value, ≤256 bytes |
| `issued_at` / `expires_at` | `i64` | unix seconds; claims always expire |
| `nonce` | `[u8;32]` | uniqueness |
| `provenance_hash` | `[u8;32]` | SHA-256 of the TLSNotary presentation |

`claim_id = SHA256(borsh(claim))`; signatures cover
`"WEBPROOF_SOLANA_CLAIM_V1" || borsh(claim)` — never JSON, never ambiguous
string concatenation. Rust and TypeScript byte-equality is pinned by the
golden vectors in [`test-vectors/`](test-vectors), asserted by tests in both
languages.

## Security Model

* **No signature without verification**: the only path to `ClaimSigner`'s
  signature goes through a `TlsnProofVerifier` implementation;
  `TlsnPresentationVerifier` only yields data after
  `Presentation::verify` succeeds (notary signature, server certificate
  chain + identity proof, transcript MAC proofs).
* Exact, structured hostname comparison against an allowlist
  (`api.example.com.attacker.com` is rejected), HTTPS-only expected URLs.
* Structured JSON parsing (JSON pointer, scalars only) — no regex.
* Onchain: version, bounded lengths, `expires_at > issued_at`, expiry,
  30-second future skew, configured max age, exact Ed25519
  message/key/offset verification, replay rejection via immutable PDA.
* Domain separation prevents cross-protocol signature reuse.
* Never commit signer or deployer keys (`WEBPROOF_SIGNER_KEY` comes from the
  environment; see `.env.example`).

## Trust Assumptions

This prototype is **not trustless** — see [docs/trust-model.md](docs/trust-model.md):

* Solana trusts the single configured WebProof verifier key to translate
  only successfully verified TLSNotary presentations into claims.
* In the local demo the TLSNotary notary runs in-process with the prover
  (the official example's pattern; the pinned release ships no standalone
  notary server). A production deployment would use an independent notary.

Future trust minimization (roadmap, not implemented): direct attestation
verification, ZK/SP1/Groth16 wrapping, multiple attestors, threshold
signatures, decentralized verifier networks.

## Solana Devnet Deployment

Devnet deployment is executed from a machine with devnet access:

```bash
bash scripts/deploy-devnet.sh    # deploys under your own program id
WEBPROOF_PROGRAM_ID=<program id> pnpm demo:devnet
```

<!-- Fill in after running the deployment: -->
| | |
|---|---|
| Network | devnet |
| Program ID | _pending deployment_ |
| Config PDA | _pending deployment_ |
| Verifier public key | _pending deployment_ |
| Example transaction | _pending deployment_ |
| Example claim PDA | _pending deployment_ |

## Tests

```bash
cargo fmt --check && cargo clippy --workspace --all-targets && cargo test --workspace
(cd crates/tlsn-demo && cargo fmt --check && cargo clippy --workspace --all-targets && cargo test --release --features fixture)
pnpm lint && pnpm test
anchor test        # 19-case onchain matrix: signatures, tampering, freshness, replay
pnpm demo:local    # real-TLSNotary E2E with round-trip assertions
```

Covered: canonical serialization golden vectors (Rust + TS), claim
validation, signature tamper matrix, TLSNotary presentation tampering /
untrusted notary / deceptive host / missing field, and the full onchain
rejection matrix (wrong verifier, missing/non-adjacent Ed25519 instruction,
message mismatch, modified claim, expired, future-issued, too-old, invalid
version, duplicate, oversized/empty fields).

## Use Cases

Account status, reputation, credentials, membership, financial account
predicates, shipping status, API-generated risk scores, AI-agent API
responses — application-specific Web2 facts with no standardized oracle feed.

## Why not a traditional oracle?

Traditional networks such as Pyth are excellent for standardized BTC/USD,
SOL/USD, ETH/USD feeds. WebProof targets **arbitrary authenticated HTTPS
data** from services that never integrate with Solana. The price demo is only
an understandable example.

## Roadmap

* Devnet deployment evidence in this README.
* Finer-grained JSON disclosure (reveal only the claimed field; the MVP
  reveals the full response body to the verifier — tracked as a TODO).
* Independent/hosted notary support when the pinned release line ships one.
* Trust minimization (see above).

## Non-goals

Production oracle networking, decentralized verifier sets, staking,
token/governance, mainnet, arbitrary HTTP methods, authenticated private
APIs, browser/mobile apps, x402, AI-agent integration, SP1/Groth16/Noir ZK
predicates, multiple data sources, frontend.

## License

Apache-2.0. See [LICENSE](LICENSE).
