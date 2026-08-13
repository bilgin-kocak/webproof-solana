#!/usr/bin/env bash
# Deploys the webproof program to Solana devnet under YOUR OWN program id.
#
# Prerequisites: solana CLI + anchor CLI installed, a funded devnet keypair
# at ~/.config/solana/id.json (use `solana airdrop 2 --url devnet` or the
# faucet at https://faucet.solana.com).
#
# After this script finishes it prints the program id, config PDA, verifier
# public key and an example transaction — copy them into README.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# 1. Program keypair: generate one if missing (never commit it).
if [ ! -f target/deploy/webproof-keypair.json ]; then
  mkdir -p target/deploy
  solana-keygen new --no-bip39-passphrase -s -o target/deploy/webproof-keypair.json
fi

# 2. Sync declare_id!/Anchor.toml with the keypair, then build and deploy.
anchor keys sync
anchor build
anchor deploy --provider.cluster devnet

PROGRAM_ID=$(solana-keygen pubkey target/deploy/webproof-keypair.json)
echo
echo "Program deployed to devnet: $PROGRAM_ID"
echo
echo "Now run the end-to-end demo against devnet:"
echo "  WEBPROOF_PROGRAM_ID=$PROGRAM_ID pnpm demo:devnet"
echo
echo "Then add to README.md: the program id above plus the transaction"
echo "signature and claim PDA printed by the demo."
