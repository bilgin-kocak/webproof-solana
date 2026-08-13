use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    ed25519_program,
    hash::hash,
    sysvar::instructions::{load_current_index_checked, load_instruction_at_checked},
};
use borsh::BorshSerialize;

declare_id!("11111111111111111111111111111111");
const DOMAIN: &[u8] = b"WEBPROOF_SOLANA_CLAIM_V1";
const FUTURE_SKEW: i64 = 30;

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
        validate_claim(
            &claim,
            Clock::get()?.unix_timestamp,
            ctx.accounts.config.max_claim_age_seconds,
        )?;
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
        let now = Clock::get()?.unix_timestamp;
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

#[account]
#[derive(InitSpace)]
pub struct WebProofConfig {
    pub authority: Pubkey,
    pub verifier_pubkey: [u8; 32],
    pub max_claim_age_seconds: i64,
    pub bump: u8,
}
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

fn validate_claim(c: &ClaimV1, now: i64, max_age: i64) -> Result<()> {
    require!(c.version == 1, WebProofError::InvalidVersion);
    require!(
        !c.source_host.is_empty() && c.source_host.len() <= 128,
        WebProofError::InvalidLength
    );
    require!(
        !c.claim_key.is_empty() && c.claim_key.len() <= 128,
        WebProofError::InvalidLength
    );
    require!(
        !c.claim_value.is_empty() && c.claim_value.len() <= 256,
        WebProofError::InvalidLength
    );
    require!(c.expires_at > c.issued_at, WebProofError::InvalidTimeWindow);
    require!(now <= c.expires_at, WebProofError::Expired);
    require!(
        c.issued_at <= now.saturating_add(FUTURE_SKEW),
        WebProofError::Future
    );
    require!(
        now.saturating_sub(c.issued_at) <= max_age,
        WebProofError::TooOld
    );
    Ok(())
}

fn u16_at(d: &[u8], i: usize) -> Result<usize> {
    d.get(i..i + 2)
        .and_then(|x| x.try_into().ok())
        .map(u16::from_le_bytes)
        .map(usize::from)
        .ok_or(error!(WebProofError::MalformedEd25519))
}
fn verify_preceding_ed25519(sysvar: &AccountInfo, key: &[u8; 32], message: &[u8]) -> Result<()> {
    let current = load_current_index_checked(sysvar)
        .map_err(|_| error!(WebProofError::MissingSignature))? as usize;
    require!(current > 0, WebProofError::MissingSignature);
    let ix = load_instruction_at_checked(current - 1, sysvar)
        .map_err(|_| error!(WebProofError::MissingSignature))?;
    require_keys_eq!(
        ix.program_id,
        ed25519_program::ID,
        WebProofError::MissingSignature
    );
    let d = &ix.data;
    require!(d.len() >= 16 && d[0] == 1, WebProofError::MalformedEd25519);
    let sig_off = u16_at(d, 2)?;
    let sig_ix = u16_at(d, 4)?;
    let key_off = u16_at(d, 6)?;
    let key_ix = u16_at(d, 8)?;
    let msg_off = u16_at(d, 10)?;
    let msg_len = u16_at(d, 12)?;
    let msg_ix = u16_at(d, 14)?;
    require!(
        sig_ix == u16::MAX as usize && key_ix == u16::MAX as usize && msg_ix == u16::MAX as usize,
        WebProofError::MalformedEd25519
    );
    require!(
        d.get(key_off..key_off + 32) == Some(key.as_slice()),
        WebProofError::WrongVerifier
    );
    require!(
        d.get(msg_off..msg_off + msg_len) == Some(message),
        WebProofError::MessageMismatch
    );
    require!(
        d.get(sig_off..sig_off + 64).is_some(),
        WebProofError::MalformedEd25519
    );
    Ok(())
}

#[error_code]
pub enum WebProofError {
    #[msg("invalid max age")]
    InvalidMaxAge,
    #[msg("unsupported claim version")]
    InvalidVersion,
    #[msg("invalid field length")]
    InvalidLength,
    #[msg("invalid time window")]
    InvalidTimeWindow,
    #[msg("claim expired")]
    Expired,
    #[msg("claim issued in future")]
    Future,
    #[msg("claim too old")]
    TooOld,
    #[msg("claim id mismatch")]
    ClaimIdMismatch,
    #[msg("signature instruction must immediately precede submit")]
    MissingSignature,
    #[msg("malformed Ed25519 instruction")]
    MalformedEd25519,
    #[msg("wrong verifier")]
    WrongVerifier,
    #[msg("signed message differs from claim")]
    MessageMismatch,
    #[msg("serialization failed")]
    Serialization,
}
