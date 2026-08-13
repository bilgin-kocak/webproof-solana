import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha256";
import { describe, expect, it } from "vitest";
import {
  claimId,
  ClaimV1,
  decodeVerifiedClaim,
  parseSignedClaim,
  serializeClaim,
  signingMessage,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, "..", "..", "..", "test-vectors");

// The fixture claim mirrored by crates/webproof-core's golden-vector test.
const claim: ClaimV1 = {
  version: 1,
  sourceHost: "api.example.com",
  requestPathHash: new Uint8Array(32).fill(1),
  claimKey: "price",
  claimValue: "12345.67",
  issuedAt: 1700000000n,
  expiresAt: 1700000300n,
  nonce: new Uint8Array(32).fill(2),
  provenanceHash: new Uint8Array(32).fill(3),
};

describe("canonical serialization", () => {
  it("matches the shared golden vector byte-for-byte", () => {
    const expectedHex = readFileSync(join(vectorsDir, "claim-v1.hex"), "utf8").trim();
    expect(Buffer.from(serializeClaim(claim)).toString("hex")).toBe(expectedHex);
  });

  it("matches the JSON golden vector metadata", () => {
    const vector = JSON.parse(readFileSync(join(vectorsDir, "claim-v1.json"), "utf8"));
    expect(Buffer.from(serializeClaim(claim)).toString("hex")).toBe(vector.canonical_hex);
    expect(Buffer.from(claimId(claim)).toString("hex")).toBe(vector.claim_id_hex);
  });

  it("domain separates signatures", () => {
    const message = signingMessage(claim);
    expect(message.subarray(0, 24).toString()).toBe("WEBPROOF_SOLANA_CLAIM_V1");
    expect(message.subarray(24)).toEqual(serializeClaim(claim));
  });
});

describe("signed-claim.json interop", () => {
  it("round-trips a signed claim file", () => {
    const file = {
      claim: {
        version: 1,
        source_host: claim.sourceHost,
        request_path_hash: Array.from(claim.requestPathHash),
        claim_key: claim.claimKey,
        claim_value: claim.claimValue,
        issued_at: Number(claim.issuedAt),
        expires_at: Number(claim.expiresAt),
        nonce: Array.from(claim.nonce),
        provenance_hash: Array.from(claim.provenanceHash),
      },
      claimId: Array.from(claimId(claim)),
      signature: Array.from(new Uint8Array(64)),
      verifierPublicKey: Array.from(new Uint8Array(32)),
      tlsnArtifactHash: Array.from(claim.provenanceHash),
    };
    const parsed = parseSignedClaim(file);
    expect(Buffer.from(serializeClaim(parsed.claim))).toEqual(Buffer.from(serializeClaim(claim)));
  });

  it("rejects a file whose claimId disagrees with the claim", () => {
    const file = {
      claim: {
        version: 1,
        source_host: claim.sourceHost,
        request_path_hash: Array.from(claim.requestPathHash),
        claim_key: claim.claimKey,
        claim_value: "tampered",
        issued_at: Number(claim.issuedAt),
        expires_at: Number(claim.expiresAt),
        nonce: Array.from(claim.nonce),
        provenance_hash: Array.from(claim.provenanceHash),
      },
      claimId: Array.from(claimId(claim)),
      signature: Array.from(new Uint8Array(64)),
      verifierPublicKey: Array.from(new Uint8Array(32)),
      tlsnArtifactHash: Array.from(claim.provenanceHash),
    };
    expect(() => parseSignedClaim(file)).toThrow(/claimId/);
  });
});

describe("VerifiedClaim account decoding", () => {
  it("decodes a synthetic account buffer", () => {
    const disc = Buffer.from(sha256(Buffer.from("account:VerifiedClaim")).slice(0, 8));
    const str = (s: string) => {
      const b = Buffer.from(s);
      const n = Buffer.alloc(4);
      n.writeUInt32LE(b.length);
      return Buffer.concat([n, b]);
    };
    const i64 = (v: bigint) => {
      const b = Buffer.alloc(8);
      b.writeBigInt64LE(v);
      return b;
    };
    const data = Buffer.concat([
      disc,
      Buffer.from(claimId(claim)),
      str(claim.sourceHost),
      Buffer.from(claim.requestPathHash),
      str(claim.claimKey),
      str(claim.claimValue),
      i64(claim.issuedAt),
      i64(claim.expiresAt),
      Buffer.from(claim.provenanceHash),
      Buffer.alloc(32),
      i64(1700000100n),
      Buffer.from([255]),
    ]);
    const decoded = decodeVerifiedClaim(data);
    expect(decoded.sourceHost).toBe(claim.sourceHost);
    expect(decoded.claimKey).toBe(claim.claimKey);
    expect(decoded.claimValue).toBe(claim.claimValue);
    expect(decoded.issuedAt).toBe(claim.issuedAt);
    expect(decoded.expiresAt).toBe(claim.expiresAt);
    expect(Buffer.from(decoded.claimId)).toEqual(Buffer.from(claimId(claim)));
    expect(decoded.bump).toBe(255);
  });
});
