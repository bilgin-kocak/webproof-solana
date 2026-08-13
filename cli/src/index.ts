/**
 * WebProof CLI.
 *
 * prove   — notarize an HTTPS GET through TLSNotary (Rust binary)
 * verify  — verify the presentation and sign a ClaimV1 (Rust binary)
 * init    — initialize the onchain config with the verifier public key
 * submit  — submit a signed claim to the webproof program
 * get     — fetch and decode a stored VerifiedClaim
 * demo    — the full pipeline in one command, with round-trip assertions
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import {
  claimId,
  parseSignedClaim,
  SignedClaimFile,
  WebProofClient,
} from "@webproof/sdk";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");
const tlsnWorkspace = join(repoRoot, "crates", "tlsn-demo");

const DEFAULT_PROGRAM_ID = "BU1KznoqTFTHgYpcvgFAS5AqqtqnwrrcjLAczpHwgKMR";

interface ChainOpts {
  rpc: string;
  programId: string;
  keypair: string;
}

function chainOptions(cmd: Command): Command {
  return cmd
    .option(
      "--rpc <url>",
      "Solana RPC URL",
      process.env.SOLANA_RPC_URL ?? "http://127.0.0.1:8899",
    )
    .option(
      "--program-id <pubkey>",
      "webproof program id",
      process.env.WEBPROOF_PROGRAM_ID ?? DEFAULT_PROGRAM_ID,
    )
    .option(
      "--keypair <path>",
      "payer keypair path",
      process.env.SOLANA_KEYPAIR ?? `${process.env.HOME}/.config/solana/id.json`,
    );
}

function clientFor(opts: ChainOpts): { client: WebProofClient; payer: Keypair; connection: Connection } {
  const connection = new Connection(opts.rpc, "confirmed");
  const payer = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(opts.keypair, "utf8"))),
  );
  return { client: new WebProofClient(connection, new PublicKey(opts.programId)), payer, connection };
}

/** Runs a Rust binary from the tlsn workspace, preferring a prebuilt release
 *  binary and falling back to `cargo run`. */
function runRust(bin: string, env: Record<string, string | undefined>): void {
  const prebuilt = join(tlsnWorkspace, "target", "release", bin);
  const merged = { ...process.env, ...env } as NodeJS.ProcessEnv;
  const result = existsSync(prebuilt)
    ? spawnSync(prebuilt, [], { stdio: "inherit", env: merged })
    : spawnSync("cargo", ["run", "--release", "--quiet", "--bin", bin], {
        stdio: "inherit",
        cwd: tlsnWorkspace,
        env: merged,
      });
  if (result.status !== 0) {
    throw new Error(`${bin} failed with status ${result.status}`);
  }
}

function artifactDir(dir?: string): string {
  return resolve(dir ?? process.env.WEBPROOF_ARTIFACT_DIR ?? join(repoRoot, "artifacts", "demo"));
}

async function confirm(connection: Connection, signature: string): Promise<void> {
  const latest = await connection.getLatestBlockhash();
  await connection.confirmTransaction({ signature, ...latest }, "confirmed");
}

const program = new Command()
  .name("webproof")
  .description("Verifiable HTTPS data for Solana using TLSNotary");

program
  .command("prove")
  .description("Notarize an HTTPS GET request through TLSNotary")
  .option("--url <url>", "HTTPS endpoint (defaults to the local test fixture)")
  .option("--field <pointer>", "JSON field to claim, e.g. price or /meta/version")
  .option("--artifact-dir <dir>", "output directory")
  .action((opts) => {
    runRust("webproof-notarize", {
      DEMO_URL: opts.url,
      DEMO_FIELD: opts.field,
      WEBPROOF_ARTIFACT_DIR: artifactDir(opts.artifactDir),
    });
  });

program
  .command("verify")
  .description("Verify the TLSNotary presentation and sign a ClaimV1")
  .option("--artifact-dir <dir>", "artifact directory from `webproof prove`")
  .action((opts) => {
    runRust("webproof-verify-sign", {
      WEBPROOF_ARTIFACT_DIR: artifactDir(opts.artifactDir),
    });
  });

chainOptions(
  program
    .command("init")
    .description("Initialize the onchain config with the trusted verifier key")
    .option("--verifier-pubkey <hex>", "verifier Ed25519 public key (hex)")
    .option("--artifact-dir <dir>", "read the verifier key from signed-claim.json")
    .option("--max-age <seconds>", "max claim age in seconds", "300"),
).action(async (opts) => {
  const { client, payer, connection } = clientFor(opts);
  let verifierKey: Uint8Array;
  if (opts.verifierPubkey) {
    verifierKey = Uint8Array.from(Buffer.from(opts.verifierPubkey, "hex"));
  } else {
    const file = JSON.parse(
      readFileSync(join(artifactDir(opts.artifactDir), "signed-claim.json"), "utf8"),
    ) as SignedClaimFile;
    verifierKey = Uint8Array.from(file.verifierPublicKey);
  }
  const signature = await client.initializeConfig({
    verifierPublicKey: verifierKey,
    maxClaimAgeSeconds: BigInt(opts.maxAge),
    authority: payer,
  });
  await confirm(connection, signature);
  console.log(`Config initialized: ${client.configAddress().toBase58()}`);
  console.log(`Transaction: ${signature}`);
});

chainOptions(
  program
    .command("submit")
    .description("Submit a signed claim to the webproof program")
    .option("--artifact-dir <dir>", "artifact directory containing signed-claim.json"),
).action(async (opts) => {
  const { client, payer, connection } = clientFor(opts);
  const parsed = parseSignedClaim(
    readFileSync(join(artifactDir(opts.artifactDir), "signed-claim.json"), "utf8"),
  );
  const { signature, claimAddress } = await client.submitClaim({
    claim: parsed.claim,
    signature: parsed.signature,
    verifierPublicKey: parsed.verifierPublicKey,
    submitter: payer,
  });
  await confirm(connection, signature);
  console.log(`Transaction: ${signature}`);
  console.log(`Claim PDA: ${claimAddress.toBase58()}`);
});

chainOptions(
  program
    .command("get")
    .description("Fetch and decode a stored VerifiedClaim")
    .requiredOption("--claim-id <hex>", "32-byte claim id (hex)"),
).action(async (opts) => {
  const { client } = clientFor(opts);
  const id = Uint8Array.from(Buffer.from(opts.claimId, "hex"));
  const stored = await client.getClaim(id);
  if (!stored) {
    console.error("claim not found");
    process.exitCode = 1;
    return;
  }
  console.log(
    JSON.stringify(
      {
        claimId: Buffer.from(stored.claimId).toString("hex"),
        sourceHost: stored.sourceHost,
        claimKey: stored.claimKey,
        claimValue: stored.claimValue,
        issuedAt: stored.issuedAt.toString(),
        expiresAt: stored.expiresAt.toString(),
        provenanceHash: Buffer.from(stored.provenanceHash).toString("hex"),
        submittedBy: stored.submittedBy.toBase58(),
        createdAt: stored.createdAt.toString(),
        address: client.claimAddress(id).toBase58(),
      },
      null,
      2,
    ),
  );
});

chainOptions(
  program
    .command("demo")
    .description("Run the full pipeline: prove, verify, init, submit, get")
    .option("--url <url>", "HTTPS endpoint (defaults to the local test fixture)")
    .option("--field <pointer>", "JSON field to claim")
    .option("--artifact-dir <dir>", "artifact directory"),
).action(async (opts) => {
  const dir = artifactDir(opts.artifactDir);

  console.log("[1/5] Requesting HTTPS data through TLSNotary...");
  runRust("webproof-notarize", {
    DEMO_URL: opts.url,
    DEMO_FIELD: opts.field,
    WEBPROOF_ARTIFACT_DIR: dir,
  });
  console.log("✓ TLS session authenticated\n");

  console.log("[2/5] Verifying transcript...");
  console.log("[3/5] Creating WebProof claim...");
  console.log("[4/5] Signing claim...");
  runRust("webproof-verify-sign", { WEBPROOF_ARTIFACT_DIR: dir });
  const parsed = parseSignedClaim(readFileSync(join(dir, "signed-claim.json"), "utf8"));
  console.log("✓ Source authenticated");
  console.log(`✓ ${parsed.claim.claimKey} = ${parsed.claim.claimValue}`);
  console.log("✓ Claim signed\n");

  console.log("[5/5] Submitting to Solana...");
  const { client, payer, connection } = clientFor(opts);

  // Initialize the config if this validator does not have one yet.
  const configInfo = await connection.getAccountInfo(client.configAddress());
  if (!configInfo) {
    const sig = await client.initializeConfig({
      verifierPublicKey: parsed.verifierPublicKey,
      maxClaimAgeSeconds: 300n,
      authority: payer,
    });
    await confirm(connection, sig);
  }

  const { signature, claimAddress } = await client.submitClaim({
    claim: parsed.claim,
    signature: parsed.signature,
    verifierPublicKey: parsed.verifierPublicKey,
    submitter: payer,
  });
  await confirm(connection, signature);

  // End-to-end assertion: the stored account must contain exactly what the
  // authenticated TLSNotary flow produced.
  const stored = await client.getClaim(claimId(parsed.claim));
  if (!stored) throw new Error("stored claim not found after submission");
  const mismatch = (what: string): never => {
    throw new Error(`stored claim does not match signed claim: ${what}`);
  };
  if (stored.sourceHost !== parsed.claim.sourceHost) mismatch("source_host");
  if (stored.claimKey !== parsed.claim.claimKey) mismatch("claim_key");
  if (stored.claimValue !== parsed.claim.claimValue) mismatch("claim_value");
  if (
    Buffer.compare(
      Buffer.from(stored.provenanceHash),
      Buffer.from(parsed.claim.provenanceHash),
    ) !== 0
  ) {
    mismatch("provenance_hash");
  }

  console.log("✓ Signature verified onchain");
  console.log("✓ Claim stored\n");
  console.log(`Transaction:\n${signature}\n`);
  console.log(`Claim PDA:\n${claimAddress.toBase58()}\n`);
  console.log("✓ HTTPS provenance verified");
  console.log("✓ Claim signature verified");
  console.log("✓ Claim stored on Solana");
});

program.parseAsync(process.argv).catch((err) => {
  console.error(err.message ?? err);
  process.exit(1);
});
