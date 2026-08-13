use anchor_lang::prelude::*;

/// Singleton configuration. The verifier key it stores is the single trust
/// anchor of the program: only claims signed by this key are accepted.
#[account]
#[derive(InitSpace)]
pub struct WebProofConfig {
    pub authority: Pubkey,
    pub verifier_pubkey: [u8; 32],
    pub max_claim_age_seconds: i64,
    pub bump: u8,
}

/// An immutable, verified claim. PDA seeds: ["claim", claim_id] — creating
/// the account doubles as replay protection (duplicates fail on init).
#[account]
#[derive(InitSpace)]
pub struct VerifiedClaim {
    pub claim_id: [u8; 32],
    #[max_len(128)]
    pub source_host: String,
    pub request_path_hash: [u8; 32],
    #[max_len(128)]
    pub claim_key: String,
    #[max_len(256)]
    pub claim_value: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub provenance_hash: [u8; 32],
    pub submitted_by: Pubkey,
    pub created_at: i64,
    pub bump: u8,
}

/// The claim submitted for verification. Must serialize (Borsh) to exactly
/// the canonical bytes signed by the offchain WebProof verifier.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct ClaimV1 {
    pub version: u8,
    pub source_host: String,
    pub request_path_hash: [u8; 32],
    pub claim_key: String,
    pub claim_value: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: [u8; 32],
    pub provenance_hash: [u8; 32],
}
