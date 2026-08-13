//! WebProof: verifiable HTTPS data for Solana.
//!
//! This program does NOT implement TLS. It verifies that the configured
//! offchain WebProof verifier Ed25519-signed the exact canonical claim being
//! submitted (via the native Ed25519 program and instruction introspection)
//! and records the claim in an immutable PDA.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash;

pub mod errors;
pub mod state;
pub mod verification;

use errors::WebProofError;
use state::{ClaimV1, VerifiedClaim, WebProofConfig};
use verification::{validate_claim, verify_preceding_ed25519, DOMAIN};

declare_id!("BU1KznoqTFTHgYpcvgFAS5AqqtqnwrrcjLAczpHwgKMR");

#[program]
pub mod webproof {
    use super::*;

    pub fn initialize_config(
        ctx: Context<InitializeConfig>,
        verifier_pubkey: [u8; 32],
        max_claim_age_seconds: i64,
    ) -> Result<()> {
        require!(max_claim_age_seconds > 0, WebProofError::InvalidMaxAge);
        let c = &mut ctx.accounts.config;
        c.authority = ctx.accounts.authority.key();
        c.verifier_pubkey = verifier_pubkey;
        c.max_claim_age_seconds = max_claim_age_seconds;
        c.bump = ctx.bumps.config;
        Ok(())
    }

    pub fn submit_claim(
        ctx: Context<SubmitClaim>,
        claim: ClaimV1,
        claim_id: [u8; 32],
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        validate_claim(&claim, now, ctx.accounts.config.max_claim_age_seconds)?;
        let bytes = claim
            .try_to_vec()
            .map_err(|_| error!(WebProofError::Serialization))?;
        require_keys_eq!(
            Pubkey::new_from_array(claim_id),
            Pubkey::new_from_array(hash(&bytes).to_bytes()),
            WebProofError::ClaimIdMismatch
        );
        verify_preceding_ed25519(
            &ctx.accounts.instructions,
            &ctx.accounts.config.verifier_pubkey,
            &[DOMAIN, bytes.as_slice()].concat(),
        )?;
        let out = &mut ctx.accounts.verified_claim;
        out.claim_id = claim_id;
        out.source_host = claim.source_host;
        out.request_path_hash = claim.request_path_hash;
        out.claim_key = claim.claim_key;
        out.claim_value = claim.claim_value;
        out.issued_at = claim.issued_at;
        out.expires_at = claim.expires_at;
        out.provenance_hash = claim.provenance_hash;
        out.submitted_by = ctx.accounts.submitter.key();
        out.created_at = now;
        out.bump = ctx.bumps.verified_claim;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(init, payer=authority, space=8+WebProofConfig::INIT_SPACE, seeds=[b"config"], bump)]
    pub config: Account<'info, WebProofConfig>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(claim: ClaimV1, claim_id: [u8;32])]
pub struct SubmitClaim<'info> {
    #[account(seeds=[b"config"], bump=config.bump)]
    pub config: Account<'info, WebProofConfig>,
    #[account(init, payer=submitter, space=8+VerifiedClaim::INIT_SPACE, seeds=[b"claim",claim_id.as_ref()], bump)]
    pub verified_claim: Account<'info, VerifiedClaim>,
    #[account(mut)]
    pub submitter: Signer<'info>,
    /// CHECK: constrained to the instructions sysvar address.
    #[account(address=anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}
