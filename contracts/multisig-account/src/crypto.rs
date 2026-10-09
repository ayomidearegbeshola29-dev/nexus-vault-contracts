//! Canonical Ed25519 signature checks.
//!
//! An Ed25519 signature is `R || s`, where `s` is a scalar that must be
//! reduced modulo the prime group order
//! `L = 2^252 + 27742317777372353535851937790883648493`. Because the
//! verification equation only depends on `s mod L`, a signature `(R, s)`
//! can be malleated into `(R, s + L)` — a different byte string that
//! verifies under a lenient verifier. Anything that hashes or de-duplicates
//! signatures (replay caches, transaction IDs) would treat the two as
//! distinct, so every signature entering the account is required to carry a
//! canonical `s < L` *before* it reaches host verification.

use soroban_sdk::{Bytes, BytesN, Env};

use crate::Error;

/// The Ed25519 group order `L`, little-endian (the encoding `s` uses).
pub const ED25519_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// True if the little-endian scalar `s` is strictly below the group order.
pub fn is_canonical_scalar(s: &[u8; 32]) -> bool {
    // Compare from the most significant byte down.
    for i in (0..32).rev() {
        if s[i] != ED25519_ORDER_LE[i] {
            return s[i] < ED25519_ORDER_LE[i];
        }
    }
    // s == L
    false
}

/// Reject a signature whose `s` half (bytes 32..64) is not canonical.
pub fn ensure_canonical_signature(signature: &BytesN<64>) -> Result<(), Error> {
    let bytes = signature.to_array();
    let mut s = [0u8; 32];
    s.copy_from_slice(&bytes[32..]);
    if is_canonical_scalar(&s) {
        Ok(())
    } else {
        Err(Error::NonCanonicalSignature)
    }
}

/// Canonical-check `signature`, then verify it with the host.
///
/// The host call traps on an invalid signature, so reaching `Ok(())` means
/// the signature is both canonical and valid.
pub fn verify_ed25519_canonical(
    env: &Env,
    public_key: &BytesN<32>,
    message: &Bytes,
    signature: &BytesN<64>,
) -> Result<(), Error> {
    ensure_canonical_signature(signature)?;
    env.crypto().ed25519_verify(public_key, message, signature);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MultisigAccount, MultisigAccountClient};
    use ed25519_dalek::{Signer, SigningKey};
    use soroban_sdk::{testutils::Address as _, vec, Address};

    /// Little-endian 256-bit addition (no overflow for the values used here).
    fn add_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = a[i] as u16 + b[i] as u16 + carry;
            out[i] = sum as u8;
            carry = sum >> 8;
        }
        out
    }

    fn setup() -> (Env, MultisigAccountClient<'static>) {
        let env = Env::default();
        let signer = Address::generate(&env);
        let id = env.register(MultisigAccount, (vec![&env, signer], 1u32));
        let client = MultisigAccountClient::new(&env, &id);
        (env, client)
    }

    /// Returns `(public_key, message, signature)` for a fixed key and message.
    fn signed(env: &Env) -> (BytesN<32>, Bytes, [u8; 64]) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let msg = b"nexus-vault multisig payload";
        let sig = sk.sign(msg).to_bytes();
        (
            BytesN::from_array(env, &sk.verifying_key().to_bytes()),
            Bytes::from_slice(env, msg),
            sig,
        )
    }

    /// `(R, s + L)`: the classic malleated twin of a valid signature.
    fn malleate(sig: &[u8; 64]) -> [u8; 64] {
        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..]);
        let mut out = *sig;
        out[32..].copy_from_slice(&add_le(&s, &ED25519_ORDER_LE));
        out
    }

    #[test]
    fn scalar_boundaries() {
        let mut l_minus_one = ED25519_ORDER_LE;
        l_minus_one[0] -= 1;
        let mut l_plus_one = ED25519_ORDER_LE;
        l_plus_one[0] += 1;

        assert!(is_canonical_scalar(&[0u8; 32]));
        assert!(is_canonical_scalar(&l_minus_one));
        assert!(!is_canonical_scalar(&ED25519_ORDER_LE));
        assert!(!is_canonical_scalar(&l_plus_one));
        assert!(!is_canonical_scalar(&[0xff; 32]));
    }

    #[test]
    fn valid_signature_verifies() {
        let (env, client) = setup();
        let (pk, msg, sig) = signed(&env);
        assert!(is_canonical_scalar(&sig[32..].try_into().unwrap()));
        client.verify_ed25519(&pk, &msg, &BytesN::from_array(&env, &sig));
    }

    #[test]
    fn malleated_signature_is_rejected() {
        let (env, client) = setup();
        let (pk, msg, sig) = signed(&env);
        let malleated = BytesN::from_array(&env, &malleate(&sig));
        assert_eq!(
            client.try_verify_ed25519(&pk, &msg, &malleated),
            Err(Ok(Error::NonCanonicalSignature))
        );
    }

    #[test]
    fn s_equal_to_order_is_rejected() {
        let (env, client) = setup();
        let (pk, msg, sig) = signed(&env);
        let mut forged = sig;
        forged[32..].copy_from_slice(&ED25519_ORDER_LE);
        assert_eq!(
            client.try_verify_ed25519(&pk, &msg, &BytesN::from_array(&env, &forged)),
            Err(Ok(Error::NonCanonicalSignature))
        );
    }

    #[test]
    #[should_panic]
    fn canonical_but_invalid_signature_traps() {
        let (env, client) = setup();
        let (pk, msg, mut sig) = signed(&env);
        sig[0] ^= 0x01;
        client.verify_ed25519(&pk, &msg, &BytesN::from_array(&env, &sig));
    }
}
