use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    ed25519_program,
    sysvar::instructions::{load_current_index_checked, load_instruction_at_checked},
};

use crate::errors::WebProofError;
use crate::state::ClaimV1;

/// Domain separator prefixed to the canonical claim bytes before signing.
/// Must match webproof-core and the TypeScript SDK.
pub const DOMAIN: &[u8] = b"WEBPROOF_SOLANA_CLAIM_V1";
/// Tolerated clock skew for `issued_at` in the future.
pub const FUTURE_SKEW: i64 = 30;

/// Stateless claim validation: version, bounded field lengths, and the
/// freshness window.
pub fn validate_claim(c: &ClaimV1, now: i64, max_age: i64) -> Result<()> {
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

/// Verifies that the instruction immediately preceding the current one is a
/// native Ed25519 verification of `message` under `key`.
///
/// The native Ed25519 program only attests to what its own instruction data
/// says it verified, so every offset in the header is parsed and pinned:
/// * the instruction must be at index `current - 1` (not merely "somewhere
///   in the transaction");
/// * `num_signatures` must be exactly 1;
/// * all three instruction-index fields must be `u16::MAX`, i.e. the
///   signature, public key and message must live in *this* instruction's
///   data — otherwise an attacker could point them at bytes the Ed25519
///   program never verified;
/// * the public key and the full message are byte-compared.
pub fn verify_preceding_ed25519(
    sysvar: &AccountInfo,
    key: &[u8; 32],
    message: &[u8],
) -> Result<()> {
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
