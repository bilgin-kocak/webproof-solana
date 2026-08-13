#!/usr/bin/env bash
# Runs the WebProof pipeline against Solana devnet.
#
# Prerequisites:
#   * the program is deployed to devnet (scripts/deploy-devnet.sh),
#   * a funded devnet keypair (default ~/.config/solana/id.json),
#   * WEBPROOF_SIGNER_KEY set (or one is generated for this run — the config
#     must then be initialized with the matching verifier key).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RPC_URL="${SOLANA_RPC_URL:-https://api.devnet.solana.com}"
PROGRAM_ID="${WEBPROOF_PROGRAM_ID:-vKofkBS5rcgK3V8HemwiZZygPQYd4e6GTyUGTvFRB7p}"
KEYPAIR="${SOLANA_KEYPAIR:-$HOME/.config/solana/id.json}"

echo "==> Building Rust TLSNotary binaries (release)..."
(cd "$ROOT/crates/tlsn-demo" && cargo build --release --quiet \
  --bin webproof-notarize --bin webproof-verify-sign)

echo "==> Building TypeScript SDK..."
pnpm --filter @webproof/sdk build >/dev/null

export WEBPROOF_SIGNER_KEY="${WEBPROOF_SIGNER_KEY:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
export WEBPROOF_ARTIFACT_DIR="${WEBPROOF_ARTIFACT_DIR:-$ROOT/artifacts/demo-devnet}"

ALLOWED="test-server.io"
if [ -n "${DEMO_URL:-}" ]; then
  DEMO_HOST=$(node -e "console.log(new URL(process.env.DEMO_URL).hostname)")
  ALLOWED="$ALLOWED,$DEMO_HOST"
fi
export WEBPROOF_ALLOWED_HOSTS="${WEBPROOF_ALLOWED_HOSTS:-$ALLOWED}"

pnpm --dir "$ROOT/cli" exec tsx src/index.ts demo \
  --rpc "$RPC_URL" \
  --program-id "$PROGRAM_ID" \
  --keypair "$KEYPAIR"
