//! Integration tests exercising the full TLSNotary pipeline against the
//! in-process fixture: a genuine MPC-TLS session is notarized once, then the
//! resulting presentation artifact is verified and attacked.
//!
//! Run with `cargo test --features fixture`.
#![cfg(feature = "fixture")]

use ed25519_dalek::SigningKey;
use url::Url;
use webproof_tlsn::{
    build_presentation, fixture, notarize, NotarizeConfig, ServerTrust, TlsnPresentationVerifier,
    VerifyError,
};
use webproof_verifier::{ClaimSigner, Error as SignError, TlsnProofVerifier};

struct Session {
    artifact: Vec<u8>,
    notary_key: Vec<u8>,
}

/// Notarizes one real MPC-TLS session against the in-process fixture.
/// Shared by all assertions below because notarization is expensive.
/// Retried once: under heavily constrained CPU the MPC scheduler can
/// deadlock, which `notarize` converts into a timeout error.
async fn notarized_session() -> Session {
    let mut last_err = None;
    for _ in 0..2 {
        let port = fixture::start().await.unwrap();
        let result = notarize(NotarizeConfig {
            server_addr: ("127.0.0.1".into(), port),
            server_name: fixture::SERVER_DOMAIN.into(),
            uri: fixture::FIXTURE_JSON_PATH.into(),
            extra_headers: vec![],
            server_trust: ServerTrust::Custom(vec![fixture::CA_CERT_DER.to_vec()]),
            max_sent_data: webproof_tlsn::DEFAULT_MAX_SENT_DATA,
            max_recv_data: webproof_tlsn::DEFAULT_MAX_RECV_DATA,
            notary_key: [1u8; 32],
        })
        .await;
        match result {
            Ok(session) => {
                let presentation =
                    build_presentation(&session.attestation, &session.secrets).unwrap();
                return Session {
                    artifact: bincode::serialize(&presentation).unwrap(),
                    notary_key: session.notary_verifying_key,
                };
            }
            Err(err) => last_err = Some(err),
        }
    }
    panic!("notarization failed after retry: {:?}", last_err.unwrap());
}

fn verifier(session: &Session) -> TlsnPresentationVerifier {
    TlsnPresentationVerifier::with_custom_roots(
        vec![fixture::CA_CERT_DER.to_vec()],
        vec![session.notary_key.clone()],
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn presentation_verification_and_attacks() {
    let session = notarized_session().await;

    // 1. A valid presentation verifies and yields the fixture's data.
    let verified = verifier(&session).verify(&session.artifact).unwrap();
    assert_eq!(verified.host(), fixture::SERVER_DOMAIN);
    assert_eq!(verified.path(), fixture::FIXTURE_JSON_PATH);
    assert_eq!(
        verified.response().pointer("/meta/version").unwrap(),
        &serde_json::json!(1.2)
    );

    // 2. An untrusted notary key is rejected before verification.
    let wrong_key = TlsnPresentationVerifier::with_custom_roots(
        vec![fixture::CA_CERT_DER.to_vec()],
        vec![vec![0u8; 33]],
    );
    assert!(matches!(
        wrong_key.verify(&session.artifact),
        Err(VerifyError::UntrustedNotary)
    ));

    // 3. Tampering with any single byte of the artifact breaks it (either it
    // fails to deserialize or the cryptographic verification fails).
    let mut tampered = session.artifact.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    assert!(verifier(&session).verify(&tampered).is_err());

    // 4. A truncated artifact is rejected.
    assert!(verifier(&session)
        .verify(&session.artifact[..session.artifact.len() / 2])
        .is_err());

    // 5. Garbage is rejected.
    assert!(verifier(&session).verify(b"not a presentation").is_err());

    // 6. verify_and_sign: only the verified pipeline yields a signature, and
    // host/field expectations are enforced.
    let signer = ClaimSigner::new(SigningKey::from_bytes(&[7u8; 32]));
    let url = Url::parse(&format!(
        "https://{}{}",
        fixture::SERVER_DOMAIN,
        fixture::FIXTURE_JSON_PATH
    ))
    .unwrap();
    let now = 1_700_000_000;

    let signed = signer
        .verify_and_sign(
            &verifier(&session),
            &session.artifact,
            &url,
            "/meta/version",
            now,
            300,
            [9u8; 32],
        )
        .unwrap();
    assert_eq!(signed.claim.source_host, fixture::SERVER_DOMAIN);
    assert_eq!(signed.claim.claim_value, "1.2");
    // provenance_hash binds the claim to this exact artifact.
    use sha2::Digest;
    let expected: [u8; 32] = sha2::Sha256::digest(&session.artifact).into();
    assert_eq!(signed.claim.provenance_hash, expected);

    // Deceptive host: signing refuses even though the artifact is valid.
    let evil = Url::parse("https://test-server.io.attacker.example/formats/json").unwrap();
    assert!(matches!(
        signer.verify_and_sign(
            &verifier(&session),
            &session.artifact,
            &evil,
            "/meta/version",
            now,
            300,
            [9u8; 32]
        ),
        Err(SignError::Host)
    ));

    // Missing field: refused.
    assert!(matches!(
        signer.verify_and_sign(
            &verifier(&session),
            &session.artifact,
            &url,
            "/does/not/exist",
            now,
            300,
            [9u8; 32]
        ),
        Err(SignError::Field)
    ));

    // Non-scalar field (object): refused.
    assert!(matches!(
        signer.verify_and_sign(
            &verifier(&session),
            &session.artifact,
            &url,
            "/meta",
            now,
            300,
            [9u8; 32]
        ),
        Err(SignError::Field)
    ));

    // Tampered artifact: no signature (the invariant).
    assert!(matches!(
        signer.verify_and_sign(
            &verifier(&session),
            &tampered,
            &url,
            "/meta/version",
            now,
            300,
            [9u8; 32]
        ),
        Err(SignError::Tlsn)
    ));
}
