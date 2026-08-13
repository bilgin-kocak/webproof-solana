import { sha256 } from "@noble/hashes/sha256";
import { Connection, Ed25519Program, PublicKey, SendOptions, Signer, SystemProgram, SYSVAR_INSTRUCTIONS_PUBKEY, Transaction, TransactionInstruction } from "@solana/web3.js";

export const DOMAIN_SEPARATOR = Buffer.from("WEBPROOF_SOLANA_CLAIM_V1");
export interface ClaimV1 { version:number; sourceHost:string; requestPathHash:Uint8Array; claimKey:string; claimValue:string; issuedAt:bigint; expiresAt:bigint; nonce:Uint8Array; provenanceHash:Uint8Array }
function string(value:string):Buffer { const b=Buffer.from(value); const n=Buffer.alloc(4); n.writeUInt32LE(b.length); return Buffer.concat([n,b]); }
function i64(value:bigint):Buffer { const b=Buffer.alloc(8); b.writeBigInt64LE(value); return b; }
function bytes32(value:Uint8Array):Buffer { if(value.length!==32) throw new Error("expected 32 bytes"); return Buffer.from(value); }
export function serializeClaim(c:ClaimV1):Buffer { return Buffer.concat([Buffer.from([c.version]),string(c.sourceHost),bytes32(c.requestPathHash),string(c.claimKey),string(c.claimValue),i64(c.issuedAt),i64(c.expiresAt),bytes32(c.nonce),bytes32(c.provenanceHash)]); }
export function claimId(c:ClaimV1):Uint8Array { return sha256(serializeClaim(c)); }
export function signingMessage(c:ClaimV1):Buffer { return Buffer.concat([DOMAIN_SEPARATOR,serializeClaim(c)]); }

export interface SubmitArgs { claim:ClaimV1; signature:Uint8Array; verifierPublicKey:Uint8Array; submitter:Signer; sendOptions?:SendOptions }
export class WebProofClient {
  constructor(readonly connection:Connection, readonly programId:PublicKey) {}
  configAddress():PublicKey { return PublicKey.findProgramAddressSync([Buffer.from("config")],this.programId)[0]; }
  claimAddress(id:Uint8Array):PublicKey { return PublicKey.findProgramAddressSync([Buffer.from("claim"),Buffer.from(id)],this.programId)[0]; }
  async submitClaim(a:SubmitArgs):Promise<{signature:string;claimAddress:PublicKey}> {
    const id=claimId(a.claim), address=this.claimAddress(id), message=signingMessage(a.claim);
    const verify=Ed25519Program.createInstructionWithPublicKey({publicKey:a.verifierPublicKey,message,signature:a.signature});
    // Anchor discriminator sha256("global:submit_claim")[0..8], followed by Borsh args.
    const discriminator=sha256(Buffer.from("global:submit_claim")).slice(0,8);
    const data=Buffer.concat([discriminator,serializeClaim(a.claim),Buffer.from(id)]);
    const submit=new TransactionInstruction({programId:this.programId,keys:[{pubkey:this.configAddress(),isSigner:false,isWritable:false},{pubkey:address,isSigner:false,isWritable:true},{pubkey:a.submitter.publicKey,isSigner:true,isWritable:true},{pubkey:SYSVAR_INSTRUCTIONS_PUBKEY,isSigner:false,isWritable:false},{pubkey:SystemProgram.programId,isSigner:false,isWritable:false}],data});
    const signature=await this.connection.sendTransaction(new Transaction().add(verify,submit),[a.submitter],a.sendOptions);
    return {signature,claimAddress:address};
  }
  async getClaim(id:Uint8Array):Promise<Buffer|null> { const info=await this.connection.getAccountInfo(this.claimAddress(id)); return info?.data ?? null; }
}
