import { sha256 } from "@noble/hashes/sha256";
import {
  Connection,
  Ed25519Program,
  PublicKey,
  SendOptions,
  Signer,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";

/** Domain separator prefixed to canonical claim bytes before signing.
 *  Must match webproof-core (Rust) and the onchain program. */
export const DOMAIN_SEPARATOR = Buffer.from("WEBPROOF_SOLANA_CLAIM_V1");

export interface ClaimV1 {
  version: number;
  sourceHost: string;
  requestPathHash: Uint8Array;
  claimKey: string;
  claimValue: string;
  issuedAt: bigint;
  expiresAt: bigint;
  nonce: Uint8Array;
  provenanceHash: Uint8Array;
}

/** A claim decoded from an onchain VerifiedClaim account. */
export interface VerifiedClaim {
  claimId: Uint8Array;
  sourceHost: string;
  requestPathHash: Uint8Array;
  claimKey: string;
  claimValue: string;
  issuedAt: bigint;
  expiresAt: bigint;
  provenanceHash: Uint8Array;
  submittedBy: PublicKey;
  createdAt: bigint;
  bump: number;
}

// --- Canonical (Borsh) serialization -------------------------------------
// Hand-rolled to match the Rust `borsh::to_vec(ClaimV1)` byte-for-byte; the
// golden vectors under test-vectors/ pin this equivalence in both languages.

function string(value: string): Buffer {
  const b = Buffer.from(value);
  const n = Buffer.alloc(4);
  n.writeUInt32LE(b.length);
  return Buffer.concat([n, b]);
}
function i64(value: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigInt64LE(value);
  return b;
}
function bytes32(value: Uint8Array): Buffer {
  if (value.length !== 32) throw new Error("expected 32 bytes");
  return Buffer.from(value);
}

export function serializeClaim(c: ClaimV1): Buffer {
  return Buffer.concat([
    Buffer.from([c.version]),
    string(c.sourceHost),
    bytes32(c.requestPathHash),
    string(c.claimKey),
    string(c.claimValue),
    i64(c.issuedAt),
    i64(c.expiresAt),
    bytes32(c.nonce),
    bytes32(c.provenanceHash),
  ]);
}

export function claimId(c: ClaimV1): Uint8Array {
  return sha256(serializeClaim(c));
}

export function signingMessage(c: ClaimV1): Buffer {
  return Buffer.concat([DOMAIN_SEPARATOR, serializeClaim(c)]);
}

/** Anchor instruction discriminator: sha256("global:<name>")[0..8]. */
export function instructionDiscriminator(name: string): Buffer {
  return Buffer.from(sha256(Buffer.from(`global:${name}`)).slice(0, 8));
}

// --- signed-claim.json interop --------------------------------------------

/** Shape of the `signed-claim.json` file written by webproof-verify-sign. */
export interface SignedClaimFile {
  claim: {
    version: number;
    source_host: string;
    request_path_hash: number[];
    claim_key: string;
    claim_value: string;
    issued_at: number;
    expires_at: number;
    nonce: number[];
    provenance_hash: number[];
  };
  claimId: number[];
  signature: number[];
  verifierPublicKey: number[];
  tlsnArtifactHash: number[];
}

/** Parses the Rust verifier's signed-claim.json into SDK types. */
export function parseSignedClaim(json: string | SignedClaimFile): {
  claim: ClaimV1;
  signature: Uint8Array;
  verifierPublicKey: Uint8Array;
  claimId: Uint8Array;
} {
  const file: SignedClaimFile = typeof json === "string" ? JSON.parse(json) : json;
  const c = file.claim;
  const claim: ClaimV1 = {
    version: c.version,
    sourceHost: c.source_host,
    requestPathHash: Uint8Array.from(c.request_path_hash),
    claimKey: c.claim_key,
    claimValue: c.claim_value,
    issuedAt: BigInt(c.issued_at),
    expiresAt: BigInt(c.expires_at),
    nonce: Uint8Array.from(c.nonce),
    provenanceHash: Uint8Array.from(c.provenance_hash),
  };
  const id = claimId(claim);
  const expected = Uint8Array.from(file.claimId);
  if (Buffer.compare(Buffer.from(id), Buffer.from(expected)) !== 0) {
    throw new Error("claimId in file does not match canonical serialization");
  }
  return {
    claim,
    signature: Uint8Array.from(file.signature),
    verifierPublicKey: Uint8Array.from(file.verifierPublicKey),
    claimId: id,
  };
}

// --- Account decoding ------------------------------------------------------

class Reader {
  offset = 0;
  constructor(readonly buf: Buffer) {}
  bytes(n: number): Buffer {
    const out = this.buf.subarray(this.offset, this.offset + n);
    if (out.length !== n) throw new Error("account data truncated");
    this.offset += n;
    return Buffer.from(out);
  }
  string(): string {
    const len = this.bytes(4).readUInt32LE();
    return this.bytes(len).toString("utf8");
  }
  i64(): bigint {
    return this.bytes(8).readBigInt64LE();
  }
  u8(): number {
    return this.bytes(1).readUInt8();
  }
}

/** Anchor account discriminator: sha256("account:VerifiedClaim")[0..8]. */
const VERIFIED_CLAIM_DISCRIMINATOR = Buffer.from(
  sha256(Buffer.from("account:VerifiedClaim")).slice(0, 8),
);

/** Decodes a VerifiedClaim account's data. */
export function decodeVerifiedClaim(data: Buffer): VerifiedClaim {
  const r = new Reader(data);
  const discriminator = r.bytes(8);
  if (Buffer.compare(discriminator, VERIFIED_CLAIM_DISCRIMINATOR) !== 0) {
    throw new Error("not a VerifiedClaim account");
  }
  return {
    claimId: r.bytes(32),
    sourceHost: r.string(),
    requestPathHash: r.bytes(32),
    claimKey: r.string(),
    claimValue: r.string(),
    issuedAt: r.i64(),
    expiresAt: r.i64(),
    provenanceHash: r.bytes(32),
    submittedBy: new PublicKey(r.bytes(32)),
    createdAt: r.i64(),
    bump: r.u8(),
  };
}

// --- Client ----------------------------------------------------------------

export interface SubmitArgs {
  claim: ClaimV1;
  signature: Uint8Array;
  verifierPublicKey: Uint8Array;
  submitter: Signer;
  sendOptions?: SendOptions;
}

export interface InitializeConfigArgs {
  verifierPublicKey: Uint8Array;
  maxClaimAgeSeconds: bigint;
  authority: Signer;
  sendOptions?: SendOptions;
}

export class WebProofClient {
  constructor(
    readonly connection: Connection,
    readonly programId: PublicKey,
  ) {}

  configAddress(): PublicKey {
    return PublicKey.findProgramAddressSync([Buffer.from("config")], this.programId)[0];
  }

  claimAddress(id: Uint8Array): PublicKey {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("claim"), Buffer.from(id)],
      this.programId,
    )[0];
  }

  private discriminator(name: string): Buffer {
    return instructionDiscriminator(name);
  }

  initializeConfigInstruction(args: {
    verifierPublicKey: Uint8Array;
    maxClaimAgeSeconds: bigint;
    authority: PublicKey;
  }): TransactionInstruction {
    const data = Buffer.concat([
      this.discriminator("initialize_config"),
      bytes32(args.verifierPublicKey),
      i64(args.maxClaimAgeSeconds),
    ]);
    return new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: this.configAddress(), isSigner: false, isWritable: true },
        { pubkey: args.authority, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });
  }

  async initializeConfig(args: InitializeConfigArgs): Promise<string> {
    const ix = this.initializeConfigInstruction({
      verifierPublicKey: args.verifierPublicKey,
      maxClaimAgeSeconds: args.maxClaimAgeSeconds,
      authority: args.authority.publicKey,
    });
    return this.connection.sendTransaction(
      new Transaction().add(ix),
      [args.authority],
      args.sendOptions,
    );
  }

  /** Builds the [Ed25519 verify, submit_claim] instruction pair. The Ed25519
   *  instruction must immediately precede submit_claim in the transaction. */
  submitClaimInstructions(a: {
    claim: ClaimV1;
    signature: Uint8Array;
    verifierPublicKey: Uint8Array;
    submitter: PublicKey;
  }): { instructions: TransactionInstruction[]; claimAddress: PublicKey } {
    const id = claimId(a.claim);
    const address = this.claimAddress(id);
    const message = signingMessage(a.claim);
    const verify = Ed25519Program.createInstructionWithPublicKey({
      publicKey: a.verifierPublicKey,
      message,
      signature: a.signature,
    });
    const data = Buffer.concat([
      this.discriminator("submit_claim"),
      serializeClaim(a.claim),
      Buffer.from(id),
    ]);
    const submit = new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: this.configAddress(), isSigner: false, isWritable: false },
        { pubkey: address, isSigner: false, isWritable: true },
        { pubkey: a.submitter, isSigner: true, isWritable: true },
        { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });
    return { instructions: [verify, submit], claimAddress: address };
  }

  async submitClaim(a: SubmitArgs): Promise<{ signature: string; claimAddress: PublicKey }> {
    const { instructions, claimAddress } = this.submitClaimInstructions({
      claim: a.claim,
      signature: a.signature,
      verifierPublicKey: a.verifierPublicKey,
      submitter: a.submitter.publicKey,
    });
    const signature = await this.connection.sendTransaction(
      new Transaction().add(...instructions),
      [a.submitter],
      a.sendOptions,
    );
    return { signature, claimAddress };
  }

  /** Fetches and decodes a VerifiedClaim by claim id. Returns null if the
   *  claim has not been stored. */
  async getClaim(id: Uint8Array): Promise<VerifiedClaim | null> {
    const info = await this.connection.getAccountInfo(this.claimAddress(id));
    return info ? decodeVerifiedClaim(info.data) : null;
  }

  /** Raw account bytes for a claim (including discriminator). */
  async getClaimRaw(id: Uint8Array): Promise<Buffer | null> {
    const info = await this.connection.getAccountInfo(this.claimAddress(id));
    return info?.data ?? null;
  }
}
