//! Tests for the multi-party Ed25519 signature aggregation validator
//! (issue #394).

extern crate std;

use crate::{signatures, Error};

use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{testutils::Address as _, vec, Address, Bytes, BytesN, Env, Vec};

/// Deploy the receipt-anchor contract so `env.current_contract_address()`
/// resolves to a real contract id during host verification.
fn setup() -> (Env, crate::ReceiptAnchorClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(crate::ReceiptAnchor, ());
    let client = crate::ReceiptAnchorClient::new(&env, &contract_id);
    (env, client)
}

/// Build `n` signer keypairs and their public keys in mask order.
fn keys(env: &Env, n: u32) -> (Vec<BytesN<32>>, std::vec::Vec<SigningKey>) {
    let mut pubkeys = vec![env];
    let mut sks = std::vec::Vec::new();
    for i in 0..n {
        let sk = SigningKey::from_bytes(&[(i + 1) as u8; 32]);
        pubkeys.push_back(BytesN::from_array(env, &sk.verifying_key().to_bytes()));
        sks.push(sk);
    }
    (pubkeys, sks)
}

fn payload(env: &Env) -> Bytes {
    Bytes::from_slice(env, &[42u8; 64])
}

/// The canonical message, rebuilt byte-for-byte the same way as
/// `signatures::canonical_message(env, ...)` for `env`, so a test can sign
/// the exact bytes the host at `env` will verify.
fn msg_bytes(
    _env: &Env,
    domain: &Bytes,
    payload: &Bytes,
    signer_pubkeys: &Vec<BytesN<32>>,
    signer_mask: u32,
) -> std::vec::Vec<u8> {
    let mut m = std::vec::Vec::new();
    m.extend_from_slice(&domain.len().to_be_bytes());
    for b in domain.iter() {
        m.push(b);
    }
    m.extend_from_slice(&payload.len().to_be_bytes());
    for b in payload.iter() {
        m.push(b);
    }
    m.extend_from_slice(&signer_pubkeys.len().to_be_bytes());
    for pk in signer_pubkeys.iter() {
        m.extend_from_slice(&pk.to_array());
    }
    m.extend_from_slice(&signer_mask.to_be_bytes());
    m
}

/// A fixed domain string used in tests (a contract would pass its own
/// strkey bytes here).
fn test_domain(env: &Env) -> Bytes {
    Bytes::from_slice(
        env,
        b"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
    )
}

/// Sign the canonical message with `sk`.
fn sign_to_env(env: &Env, sk: &SigningKey, raw: &[u8]) -> BytesN<64> {
    let sig = sk.sign(raw);
    BytesN::from_array(env, &sig.to_bytes())
}

// ── Mask validation ──────────────────────────────────────────────────────────

#[test]
fn zero_mask_rejected() {
    let (env, _client) = setup();
    let (pubkeys, _sks) = keys(&env, 2);
    assert_eq!(
        signatures::validate_mask(&pubkeys, 0),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn mask_bits_beyond_key_list_rejected() {
    let (env, _client) = setup();
    let (pubkeys, _sks) = keys(&env, 2);
    // Bit 2 set but only 2 keys (bits 0..=1) exist.
    assert_eq!(
        signatures::validate_mask(&pubkeys, 0b100),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        signatures::validate_mask(&pubkeys, 0b111),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn toomany_signers_rejected() {
    let (env, _client) = setup();
    let mut long = vec![&env];
    // 33 keys — one beyond `MAX_SIGNERS`.
    for i in 0..=32u8 {
        let sk = SigningKey::from_bytes(&[i.wrapping_add(1); 32]);
        long.push_back(BytesN::from_array(&env, &sk.verifying_key().to_bytes()));
    }
    assert_eq!(
        signatures::validate_mask(&long, 1),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn well_formed_mask_accepted() {
    let (env, _client) = setup();
    let (pubkeys, _sks) = keys(&env, 3);
    assert_eq!(signatures::validate_mask(&pubkeys, 0b101), Ok(()));
    assert_eq!(signatures::validate_mask(&pubkeys, 0b111), Ok(()));
}

// ── Aggregated verification ──────────────────────────────────────────────────

#[test]
fn aggregate_verifies_for_all_masked_signers() {
    let (env, _client) = setup();
    let (pubkeys, sks) = keys(&env, 3);
    let mask = 0b111u32;

    let raw = msg_bytes(&env, &test_domain(&env), &payload(&env), &pubkeys, mask);
    let sig = sign_to_env(&env, &sks[0], &raw);

    assert!(signatures::verify_aggregated_signature(
        &env,
        &test_domain(&env),
        &payload(&env),
        &pubkeys,
        mask,
        &sig
    )
    .unwrap());
}

#[test]
fn aggregate_rejects_forged_sub_signature() {
    let (env, _client) = setup();
    let (pubkeys, _sks) = keys(&env, 3);
    let mask = 0b101u32;

    // A key that is NOT in the participant list (an attacker's own key)
    // produces a signature that must fail the host verification for the
    // designated aggregator key.
    let raw = msg_bytes(&env, &test_domain(&env), &payload(&env), &pubkeys, mask);
    let forged = SigningKey::from_bytes(&[9u8; 32]);
    let wrong = sign_to_env(&env, &forged, &raw);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        signatures::verify_aggregated_signature(
            &env,
            &test_domain(&env),
            &payload(&env),
            &pubkeys,
            mask,
            &wrong,
        )
    }));
    assert!(result.is_err(), "forged aggregate must be rejected");
}

#[test]
fn individual_verification_for_each_masked_signer() {
    let (env, _client) = setup();
    let (pubkeys, sks) = keys(&env, 3);
    let mask = 0b111u32;

    let payload = payload(&env);
    let raw = msg_bytes(&env, &test_domain(&env), &payload, &pubkeys, mask);
    for (i, sk) in sks.iter().enumerate() {
        let sig = sign_to_env(&env, sk, &raw);
        assert!(signatures::verify_individual_signature(
            &env,
            &test_domain(&env),
            &payload,
            &pubkeys,
            mask,
            i as u32,
            &sig
        )
        .unwrap());
    }
}

#[test]
fn individual_verification_rejects_unmasked_signer() {
    let (env, _client) = setup();
    let (pubkeys, _sks) = keys(&env, 3);
    let payload = payload(&env);
    let mask = 0b001u32; // only participant 0 signed.

    // Participant 1 is not in the mask: auditing it is a spec violation.
    assert_eq!(
        signatures::verify_individual_signature(
            &env,
            &test_domain(&env),
            &payload,
            &pubkeys,
            mask,
            1,
            &BytesN::from_array(&env, &[0u8; 64])
        ),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn aggregator_key_is_first_masked_participant() {
    let (env, _client) = setup();
    let (pubkeys, _sks) = keys(&env, 4);
    assert_eq!(
        signatures::aggregator_key(&pubkeys, 0b010),
        Ok(pubkeys.get(1).unwrap())
    );
    assert_eq!(
        signatures::aggregator_key(&pubkeys, 0b1000),
        Ok(pubkeys.get(3).unwrap())
    );
}

// ── Replay / binding ─────────────────────────────────────────────────────────

#[test]
fn signature_binds_the_contract_id() {
    let (env, _client) = setup();
    let (pubkeys, sks) = keys(&env, 2);
    let mask = 0b11u32;

    // Sign a message bound to a *different* contract (`env2`'s address);
    // verifying it in `env` must reject it.
    let (env, _client) = setup();
    let (env2, _client2) = setup();
    let payload_b = payload(&env);
    let dom1 = test_domain(&env);
    let dom2 = Bytes::from_slice(
        &env2,
        b"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KMX",
    );
    let raw2 = msg_bytes(&env2, &dom2, &payload_b, &pubkeys, mask);
    let sig = sign_to_env(&env, &sks[0], &raw2);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        signatures::verify_aggregated_signature(&env, &dom1, &payload_b, &pubkeys, mask, &sig)
    }));
    assert!(result.is_err(), "cross-contract signature must be rejected");
}

#[test]
fn aggregate_roundtrip_single_use() {
    let (env, _client) = setup();
    let (pubkeys, sks) = keys(&env, 1);
    let payload = payload(&env);
    let mask = 1u32;

    let raw = msg_bytes(&env, &test_domain(&env), &payload, &pubkeys, mask);
    let sig = sign_to_env(&env, &sks[0], &raw);
    assert!(signatures::verify_individual_signature(
        &env,
        &test_domain(&env),
        &payload,
        &pubkeys,
        mask,
        0,
        &sig
    )
    .unwrap());
    assert!(signatures::verify_aggregated_signature(
        &env,
        &test_domain(&env),
        &payload,
        &pubkeys,
        mask,
        &sig
    )
    .unwrap());
}

#[test]
fn address_import_available() {
    let env = Env::default();
    let _addr = Address::generate(&env);
}
