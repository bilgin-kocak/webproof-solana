#!/usr/bin/env bash
# Runs the complete WebProof pipeline against a local solana-test-validator:
#   TLSNotary (MPC-TLS, in-process notary + HTTPS fixture)
#     -> WebProof verifier -> signed ClaimV1 -> Solana -> VerifiedClaim PDA
#
# Requirements on PATH: cargo, solana-test-validator, solana-keygen, pnpm.
# The Anchor program must be built (anchor build) or target/deploy/webproof.so
# must exist.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROGRAM_ID="BU1KznoqTFTHgYpcvgFAS5AqqtqnwrrcjLAczpHwgKMR"
RPC_PORT="${RPC_PORT:-8899}"
RPC_URL="http://127.0.0.1:${RPC_PORT}"
DEMO_DIR="$ROOT/.demo"
PAYER="$DEMO_DIR/payer.json"

mkdir -p "$DEMO_DIR"

echo "==> Building Rust TLSNotary binaries (release)..."
(cd "$ROOT/crates/tlsn-demo" && cargo build --release --quiet \
  --bin webproof-notarize --bin webproof-verify-sign)

if [ ! -f "$ROOT/target/deploy/webproof.so" ]; then
  echo "==> target/deploy/webproof.so missing; building with anchor..."
  (cd "$ROOT" && anchor build)
fi

echo "==> Building TypeScript SDK..."
pnpm --filter @webproof/sdk build >/dev/null

[ -f "$PAYER" ] || solana-keygen new --no-bip39-passphrase -s -o "$PAYER" >/dev/null

echo "==> Starting solana-test-validator..."
solana-test-validator --reset --quiet \
  --ledger "$DEMO_DIR/ledger" \
  --rpc-port "$RPC_PORT" \
  --bpf-program "$PROGRAM_ID" "$ROOT/target/deploy/webproof.so" \
  >"$DEMO_DIR/validator.log" 2>&1 &
VALIDATOR_PID=$!
trap 'kill "$VALIDATOR_PID" 2>/dev/null || true' EXIT

for i in $(seq 1 60); do
  if curl -s "$RPC_URL" -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' 2>/dev/null | grep -q '"ok"'; then
    break
  fi
  [ "$i" = 60 ] && { echo "validator did not become healthy"; exit 1; }
  sleep 1
done

solana airdrop 10 "$(solana-keygen pubkey "$PAYER")" --url "$RPC_URL" >/dev/null

# Ephemeral verifier signing key for this run. Never commit a real key.
export WEBPROOF_SIGNER_KEY="${WEBPROOF_SIGNER_KEY:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
export WEBPROOF_ARTIFACT_DIR="${WEBPROOF_ARTIFACT_DIR:-$ROOT/artifacts/demo-local}"

# Host allowlist: the local fixture by default, plus the DEMO_URL host if set.
ALLOWED="test-server.io"
if [ -n "${DEMO_URL:-}" ]; then
  DEMO_HOST=$(node -e "console.log(new URL(process.env.DEMO_URL).hostname)")
  ALLOWED="$ALLOWED,$DEMO_HOST"
fi
export WEBPROOF_ALLOWED_HOSTS="${WEBPROOF_ALLOWED_HOSTS:-$ALLOWED}"

pnpm --dir "$ROOT/cli" exec tsx src/index.ts demo \
  --rpc "$RPC_URL" \
  --program-id "$PROGRAM_ID" \
  --keypair "$PAYER"
