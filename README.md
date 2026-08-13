# WebProof

**Verifiable HTTPS data for Solana using TLSNotary.**

Solana programs cannot directly query Web2 HTTPS APIs. WebProof allows an offchain TLSNotary session to authenticate data returned by an HTTPS server and makes the resulting claim usable by Solana programs.

> **Implementation status:** the canonical claim, gated signer boundary, SDK transaction construction, and Anchor program are implemented. The real TLSNotary spike, validator E2E, and devnet deployment are explicitly release-blocked because official TLSNotary sources and Solana tooling were unavailable in this build environment. No ordinary-HTTPS or mock result is presented as an E2E proof. See [the dependency record](docs/tlsnotary-version.md).

## Why WebProof?

```text
HTTPS API → TLSNotary → WebProof Verifier → Signed Claim → Solana
```

A normal Web2 provider need not add a blockchain integration. The program never runs TLS: it trusts a configured Ed25519 verifier, while TLSNotary verification and parsing remain offchain.

> Price data is used only as a simple demonstration of authenticated HTTPS provenance. WebProof is intended primarily for Web2 data for which dedicated blockchain oracle infrastructure does not exist.

## Demo

The intended, not-yet-released command is `pnpm demo:local`. It will require a TLSNotary notary server, `solana-test-validator`, Anchor, and a signer supplied through `WEBPROOF_SIGNER_KEY`. It must print a result only after the real presentation verifies. The placeholder currently exits unsuccessfully so it cannot be mistaken for proof of completion.

## Architecture

1. An official TLSNotary prover performs the HTTPS GET and creates a selectively disclosed presentation.
2. The verifier authenticates it, exactly matches the host, and parses a scalar with a JSON Pointer.
3. It hashes the presentation and creates bounded `ClaimV1` data.
4. Ed25519 signs `WEBPROOF_SOLANA_CLAIM_V1 || borsh(claim)`.
5. The SDK puts native Ed25519 verification directly before `submit_claim`.
6. Anchor compares the configured key and exact message, validates time/bounds, and initializes `PDA("claim", SHA256(borsh(claim)))`.

See [architecture](docs/architecture.md), [trust model](docs/trust-model.md), and [security notes](docs/security.md).

## Quick Start

```bash
cp .env.example .env
cargo test -p webproof-core -p webproof-verifier
pnpm install
pnpm test
```

A release engineer must complete the official TLSNotary pinning checklist before attempting the demo.

## Claim Format

`ClaimV1` contains version, exact source host, SHA-256 request-path hash, JSON Pointer key, canonical scalar string, issuance/expiration, 32-byte nonce, and SHA-256 presentation hash. Strings are bounded to 128/128/256 UTF-8 bytes. Canonical encoding is Borsh. The cross-language vector is stored as reviewable hexadecimal text in `test-vectors/claim-v1.hex`; no binary fixture is required.

`claim_id = SHA256(borsh(ClaimV1))`; signatures use the domain-separated bytes, not JSON.

## Security Model and Trust Assumptions

The configured verifier is centralized and trusted to translate a successfully verified presentation. **WebProof is not fully trustless.** The type-gated signing API has no path from failed proof verification to a signed claim. Onchain checks include version, bounds, window, 30-second future skew, configured maximum age, expiry, exact native signature instruction contents, and replay rejection by immutable PDA creation.

Do not expose the verifier as a URL-fetching service without DNS/IP SSRF defenses. Exact hostname comparison alone does not prevent DNS rebinding.

## Why not a traditional oracle?

Traditional networks such as Pyth are excellent for standardized BTC/USD, SOL/USD, and ETH/USD feeds. WebProof targets arbitrary authenticated HTTPS data: bank-account predicates, private API responses, credentials, reputation, membership, Web2 account information, purchased data, risk scores, and application-specific APIs. The price is only an understandable example.

## Solana Devnet Deployment

No deployment is claimed. Program ID, config PDA, verifier key, transaction, and example claim PDA must be added only after a reproducible local E2E and actual devnet deployment. Never commit deployer or verifier secrets.

## Tests

```bash
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
pnpm lint
pnpm test
anchor test        # requires Anchor/Solana toolchains
pnpm demo:local    # requires completed real TLSNotary spike and validator
```

## Use Cases

Credentials, reputation, membership, account status, shipping state, API-generated scores, and other application-specific Web2 facts unavailable from standardized oracle feeds.

## Roadmap

Complete the pinned real TLSNotary spike, local validator E2E, and devnet evidence. Later work may improve fine-grained JSON disclosure and reduce verifier trust.

## Non-goals

Production oracle networking, decentralized verifier sets, staking, token/governance, mainnet, arbitrary methods, private authenticated APIs, browser/mobile apps, x402, AI-agent integration, SP1/Groth16/Noir/ZK predicates, multiple sources, and a frontend.

## License

Apache-2.0. See [LICENSE](LICENSE).
