use anchor_lang::prelude::*;

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
