/**
 * Onchain test matrix for the webproof Anchor program.
 *
 * Run via `anchor test` (which starts a local validator with the program
 * deployed and sets ANCHOR_PROVIDER_URL / ANCHOR_WALLET), or manually
 * against any validator with the program deployed.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { before, describe, it } from "node:test";
import { ed25519 } from "@noble/curves/ed25519";
import {
  Connection,
  Ed25519Program,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import {
  claimId,
  ClaimV1,
  instructionDiscriminator,
  serializeClaim,
  signingMessage,
  WebProofClient,
} from "@webproof/sdk";

const PROGRAM_ID = new PublicKey("vKofkBS5rcgK3V8HemwiZZygPQYd4e6GTyUGTvFRB7p");
const MAX_CLAIM_AGE = 300n;

const providerUrl = process.env.ANCHOR_PROVIDER_URL ?? "http://127.0.0.1:8899";
const walletPath = process.env.ANCHOR_WALLET ?? `${process.env.HOME}/.config/solana/id.json`;

const connection = new Connection(providerUrl, "confirmed");
const payer = Keypair.fromSecretKey(
  Uint8Array.from(JSON.parse(readFileSync(walletPath, "utf8"))),
);
const client = new WebProofClient(connection, PROGRAM_ID);

// The trusted verifier key for this test run.
const verifierSecret = randomBytes(32);
const verifierPublic = ed25519.getPublicKey(verifierSecret);
// An attacker key never registered in the config.
const attackerSecret = randomBytes(32);
const attackerPublic = ed25519.getPublicKey(attackerSecret);

function now(): bigint {
  return BigInt(Math.floor(Date.now() / 1000));
}

function makeClaim(overrides: Partial<ClaimV1> = {}): ClaimV1 {
  const issuedAt = now();
  return {
    version: 1,
    sourceHost: "api.example.com",
    requestPathHash: Uint8Array.from(randomBytes(32)),
    claimKey: "price",
    claimValue: "12345.67",
    issuedAt,
    expiresAt: issuedAt + 300n,
    nonce: Uint8Array.from(randomBytes(32)),
    provenanceHash: Uint8Array.from(randomBytes(32)),
    ...overrides,
  };
}

function sign(claim: ClaimV1, secret: Uint8Array = verifierSecret): Uint8Array {
  return ed25519.sign(signingMessage(claim), secret);
}

async function sendTx(tx: Transaction, signers: Keypair[]): Promise<string> {
  const sig = await connection.sendTransaction(tx, signers);
  const latest = await connection.getLatestBlockhash();
  await connection.confirmTransaction({ signature: sig, ...latest }, "confirmed");
  return sig;
}

/** Sends and expects failure; returns the combined error text (message+logs). */
async function expectFail(tx: Transaction, signers: Keypair[]): Promise<string> {
  try {
    await sendTx(tx, signers);
  } catch (err: any) {
    const logs: string[] = err.logs ?? err?.transactionLogs ?? [];
    return `${err.message}\n${logs.join("\n")}`;
  }
  throw new Error("expected transaction to fail, but it succeeded");
}

function submitTx(
  claim: ClaimV1,
  opts: {
    signature?: Uint8Array;
    verifierKey?: Uint8Array;
    message?: Uint8Array;
    id?: Uint8Array;
    omitEd25519?: boolean;
    insertBetween?: TransactionInstruction;
  } = {},
): Transaction {
  const id = opts.id ?? claimId(claim);
  const message = opts.message ?? signingMessage(claim);
  const verifierKey = opts.verifierKey ?? verifierPublic;
  const signature = opts.signature ?? sign(claim);
  const address = client.claimAddress(id);
  const verify = Ed25519Program.createInstructionWithPublicKey({
    publicKey: verifierKey,
    message: Buffer.from(message),
    signature,
  });
  const data = Buffer.concat([
    instructionDiscriminator("submit_claim"),
    serializeClaim(claim),
    Buffer.from(id),
  ]);
  const submit = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: client.configAddress(), isSigner: false, isWritable: false },
      { pubkey: address, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      {
        pubkey: new PublicKey("Sysvar1nstructions1111111111111111111111111"),
        isSigner: false,
        isWritable: false,
      },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
  const tx = new Transaction();
  if (!opts.omitEd25519) tx.add(verify);
  if (opts.insertBetween) tx.add(opts.insertBetween);
  tx.add(submit);
  return tx;
}

describe("webproof program", () => {
  before(async () => {
    // Local validators fund the default wallet; make sure it has lamports.
    const balance = await connection.getBalance(payer.publicKey);
    if (balance < 1_000_000_000) {
      const sig = await connection.requestAirdrop(payer.publicKey, 2_000_000_000);
      const latest = await connection.getLatestBlockhash();
      await connection.confirmTransaction({ signature: sig, ...latest }, "confirmed");
    }
  });

  it("rejects initialize_config with non-positive max age", async () => {
    const ix = client.initializeConfigInstruction({
      verifierPublicKey: verifierPublic,
      maxClaimAgeSeconds: 0n,
      authority: payer.publicKey,
    });
    const text = await expectFail(new Transaction().add(ix), [payer]);
    assert.match(text, /InvalidMaxAge/);
  });

  it("initializes the config", async () => {
    const ix = client.initializeConfigInstruction({
      verifierPublicKey: verifierPublic,
      maxClaimAgeSeconds: MAX_CLAIM_AGE,
      authority: payer.publicKey,
    });
    await sendTx(new Transaction().add(ix), [payer]);
    const info = await connection.getAccountInfo(client.configAddress());
    assert.ok(info, "config account should exist");
    // authority pubkey lives after the 8-byte discriminator.
    assert.deepEqual(
      new PublicKey(info.data.subarray(8, 40)).toBase58(),
      payer.publicKey.toBase58(),
    );
    // verifier key follows the authority.
    assert.deepEqual(
      Buffer.from(info.data.subarray(40, 72)),
      Buffer.from(verifierPublic),
    );
  });

  it("rejects re-initialization of the config", async () => {
    const ix = client.initializeConfigInstruction({
      verifierPublicKey: attackerPublic,
      maxClaimAgeSeconds: MAX_CLAIM_AGE,
      authority: payer.publicKey,
    });
    const text = await expectFail(new Transaction().add(ix), [payer]);
    assert.match(text, /already in use|custom program error/i);
  });

  it("accepts a valid signed claim and stores it", async () => {
    const claim = makeClaim();
    const { signature, claimAddress } = await client.submitClaim({
      claim,
      signature: sign(claim),
      verifierPublicKey: verifierPublic,
      submitter: payer,
    });
    const latest = await connection.getLatestBlockhash();
    await connection.confirmTransaction({ signature, ...latest }, "confirmed");

    const stored = await client.getClaim(claimId(claim));
    assert.ok(stored, "claim account should exist");
    assert.equal(stored.sourceHost, claim.sourceHost);
    assert.equal(stored.claimKey, claim.claimKey);
    assert.equal(stored.claimValue, claim.claimValue);
    assert.equal(stored.issuedAt, claim.issuedAt);
    assert.equal(stored.expiresAt, claim.expiresAt);
    assert.deepEqual(Buffer.from(stored.provenanceHash), Buffer.from(claim.provenanceHash));
    assert.deepEqual(Buffer.from(stored.claimId), Buffer.from(claimId(claim)));
    assert.equal(stored.submittedBy.toBase58(), payer.publicKey.toBase58());
    assert.equal(client.claimAddress(claimId(claim)).toBase58(), claimAddress.toBase58());
  });

  it("rejects a duplicate claim", async () => {
    const claim = makeClaim();
    const tx1 = submitTx(claim);
    await sendTx(tx1, [payer]);
    const text = await expectFail(submitTx(claim), [payer]);
    assert.match(text, /already in use|custom program error/i);
  });

  it("rejects a claim signed by an untrusted verifier", async () => {
    const claim = makeClaim();
    const text = await expectFail(
      submitTx(claim, {
        verifierKey: attackerPublic,
        signature: sign(claim, attackerSecret),
      }),
      [payer],
    );
    assert.match(text, /WrongVerifier/);
  });

  it("rejects a transaction without the Ed25519 instruction", async () => {
    const claim = makeClaim();
    const text = await expectFail(submitTx(claim, { omitEd25519: true }), [payer]);
    assert.match(text, /MissingSignature/);
  });

  it("rejects an Ed25519 instruction that does not immediately precede submit", async () => {
    const claim = makeClaim();
    const filler = SystemProgram.transfer({
      fromPubkey: payer.publicKey,
      toPubkey: payer.publicKey,
      lamports: 1,
    });
    const text = await expectFail(submitTx(claim, { insertBetween: filler }), [payer]);
    assert.match(text, /MissingSignature/);
  });

  it("rejects a signature over a different message", async () => {
    const claimA = makeClaim();
    const claimB = makeClaim({ claimValue: "999.99" });
    // The Ed25519 program verifies claimB's message; submit_claim gets claimA.
    const text = await expectFail(
      submitTx(claimA, {
        message: signingMessage(claimB),
        signature: sign(claimB),
      }),
      [payer],
    );
    assert.match(text, /MessageMismatch/);
  });

  it("rejects a claim modified after signing", async () => {
    const claim = makeClaim();
    const signature = sign(claim);
    const tampered = { ...claim, claimValue: "13337.00" };
    // Submit the tampered claim with its own (correct) claim_id but the
    // signature over the original message.
    const text = await expectFail(
      submitTx(tampered, {
        message: signingMessage(claim),
        signature,
      }),
      [payer],
    );
    assert.match(text, /MessageMismatch/);
  });

  it("rejects a claim_id that does not match the claim", async () => {
    const claimA = makeClaim();
    const claimB = makeClaim();
    const text = await expectFail(
      submitTx(claimA, { id: claimId(claimB) }),
      [payer],
    );
    assert.match(text, /ClaimIdMismatch/);
  });

  it("rejects an expired claim", async () => {
    const issuedAt = now() - 250n;
    const claim = makeClaim({ issuedAt, expiresAt: issuedAt + 100n });
    const text = await expectFail(submitTx(claim), [payer]);
    assert.match(text, /Expired/);
  });

  it("rejects a claim issued in the future", async () => {
    const issuedAt = now() + 120n;
    const claim = makeClaim({ issuedAt, expiresAt: issuedAt + 300n });
    const text = await expectFail(submitTx(claim), [payer]);
    assert.match(text, /Future/);
  });

  it("rejects a claim older than max_claim_age_seconds", async () => {
    const issuedAt = now() - 400n;
    const claim = makeClaim({ issuedAt, expiresAt: now() + 200n });
    const text = await expectFail(submitTx(claim), [payer]);
    assert.match(text, /TooOld/);
  });

  it("rejects an unsupported claim version", async () => {
    const claim = makeClaim({ version: 2 });
    const text = await expectFail(submitTx(claim), [payer]);
    assert.match(text, /InvalidVersion/);
  });

  it("rejects an inverted time window", async () => {
    const issuedAt = now();
    const claim = makeClaim({ issuedAt, expiresAt: issuedAt });
    const text = await expectFail(submitTx(claim), [payer]);
    assert.match(text, /InvalidTimeWindow/);
  });

  // The oversized-field claims are submitted without the Ed25519 instruction:
  // carrying a >256-byte claim twice (signed message + instruction data)
  // exceeds Solana's transaction size limit, and validate_claim runs before
  // the signature check, so the on-chain length rejection still fires.
  it("rejects an oversized source_host", async () => {
    const claim = makeClaim({ sourceHost: "h".repeat(129) });
    const text = await expectFail(submitTx(claim, { omitEd25519: true }), [payer]);
    assert.match(text, /InvalidLength/);
  });

  it("rejects an oversized claim_value", async () => {
    const claim = makeClaim({ claimValue: "v".repeat(257) });
    const text = await expectFail(submitTx(claim, { omitEd25519: true }), [payer]);
    assert.match(text, /InvalidLength/);
  });

  it("rejects an empty claim_key", async () => {
    const claim = makeClaim({ claimKey: "" });
    const text = await expectFail(submitTx(claim), [payer]);
    assert.match(text, /InvalidLength/);
  });
});
