//! Off-chain Ed25519 signature aggregation validator for multi-party
//! receipts (issue #394).
//!
//! A multi-party payment (e.g. a split purchase or a marketplace payout)
//! is authorized by *several* Ed25519 keys. Verifying each signature in its
//! own host call costs one `ed25519_verify` invocation per participant; the
//! aggregated form instead commits every participant to one canonical
//! message, records who was supposed to sign via a bitmap, and verifies the
//! single aggregated signature first — one host call instead of N — with a
//! per-key fallback that only runs on dispute.
//!
//! # Wire format
//!
//! A multi-party receipt carries:
//!
//! - `signer_pubkeys`: the participating Ed25519 public keys, in the same
//!   order the bitmap indexes.
//! - `signer_mask`: a bitmap (little-endian bit order, byte-packed) where
//!   bit `i` set means `signer_pubkeys[i]` participated.
//! - `aggregate_sig`: the single Ed25519 signature to verify. The aggregate
//!   is produced off-chain by a designated aggregator key (see
//!   [`aggregator_key`]) over the canonical message; because the message
//!   binds the full participant set and mask, that one signature commits
//!   every masked participant.
//! - `payload`: the canonical receipt bytes all signers agreed on.
//!
//! The canonical message (see [`canonical_message`]) binds, in order: the
//! contract address (domain separation), the receipt `payload`, the number
//! of signers, each signer pubkey, and the signer mask. Every element is
//! length-prefixed implicitly by its fixed width, so no two parses of the
//! same tuple can disagree.
//!
//! # Verification rules
//!
//! [`verify_aggregated_signature`] returns `Ok(true)` only when *every*
//! bit set in `signer_mask` indexes a key present in `signer_pubkeys` and
//! `aggregate_sig` verifies against the canonical message. Any invalid
//! sub-signature (i.e. a mask bit for a key that did not actually sign) is
//! a complete rejection: the aggregate must cover all participants, so a
//! forged component rejects the whole verification.
//!
//! The gas win: the common case verifies exactly one signature regardless
//! of participant count. [`verify_individual_signature`] exists for
//! auditing flows that must re-check a single participant's signature.

use crate::Error;
use soroban_sdk::{Bytes, BytesN, Env, Vec};

/// Maximum number of participants in a multi-party receipt. Bounds the
/// bitmap to 32 bits (4 bytes) and keeps the canonical message's signer
/// enumeration linear in a small constant.
pub const MAX_SIGNERS: u32 = 32;

/// The canonical message all participants sign (see the module docs).
///
/// Layout: `domain_len(u32 BE) || domain || payload_len(u32 BE) ||
/// payload || signer_count(u32 BE) || pubkey_1(32) || ... || pubkey_n(32) ||
/// mask(u32 BE)`.
///
/// `domain` is the domain-separation prefix the calling contract passes —
/// normally its own strkey bytes (`env.current_contract_address().to_string()
/// .to_bytes()`) — so signatures are only valid for the contract that
/// verified them (replay across deployments is impossible). Passing it
/// explicitly keeps these helpers callable from tests and non-contract
/// contexts, where `env.current_contract_address()` is unavailable.
pub fn canonical_message(
    env: &Env,
    domain: &Bytes,
    payload: &Bytes,
    signer_pubkeys: &Vec<BytesN<32>>,
    signer_mask: u32,
) -> Bytes {
    let mut msg = Bytes::new(env);
    // Domain separation: the verifying contract's strkey bytes.
    msg.extend_from_slice(&domain.len().to_be_bytes());
    msg.append(domain);
    // The receipt payload, length-prefixed.
    msg.extend_from_slice(&payload.len().to_be_bytes());
    msg.append(payload);
    // The participant set, enumerated in bitmap order.
    msg.extend_from_slice(&signer_pubkeys.len().to_be_bytes());
    for key in signer_pubkeys.iter() {
        msg.extend_from_slice(&key.to_array());
    }
    // The exact participation bitmap the aggregate covers.
    msg.extend_from_slice(&signer_mask.to_be_bytes());
    msg
}

/// Validate a mask against the participant list.
///
/// Returns `Err(Error::InvalidSignature)` when any set bit indexes a key
/// beyond the list, or when no bits are set (an empty aggregate proves
/// nothing). The mask's high bits beyond `MAX_SIGNERS` are structurally
/// impossible for masks within `u32` when `signer_pubkeys.len() <= 32`,
/// but the per-bit check enforces it regardless.
pub fn validate_mask(signer_pubkeys: &Vec<BytesN<32>>, signer_mask: u32) -> Result<(), Error> {
    if signer_pubkeys.len() > MAX_SIGNERS {
        return Err(Error::InvalidSignature);
    }
    if signer_mask == 0 {
        return Err(Error::InvalidSignature);
    }
    // Every set bit must correspond to a key in the list: mask out the
    // valid range and require nothing left over.
    let valid_bits = if signer_pubkeys.len() >= 32 {
        u32::MAX
    } else {
        (1u32 << signer_pubkeys.len()) - 1
    };
    if signer_mask & !valid_bits != 0 {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

/// Verify the aggregated signature for a multi-party receipt.
///
/// `Ok(true)` means: the mask is well-formed for `signer_pubkeys`, and
/// `aggregate_sig` is a valid Ed25519 signature over
/// [`canonical_message`] — which, given the message binds every listed
/// pubkey and the exact mask, proves every masked participant approved
/// `payload`. Returns `Ok(false)` (or `Err`) on any failure; a single
/// invalid component rejects the entire verification.
///
/// Gas: exactly **one** host `ed25519_verify` call regardless of the
/// number of participants, versus one per participant for individual
/// verification.
pub fn verify_aggregated_signature(
    env: &Env,
    domain: &Bytes,
    payload: &Bytes,
    signer_pubkeys: &Vec<BytesN<32>>,
    signer_mask: u32,
    aggregate_sig: &BytesN<64>,
) -> Result<bool, Error> {
    validate_mask(signer_pubkeys, signer_mask)?;

    let msg = canonical_message(env, domain, payload, signer_pubkeys, signer_mask);

    // One host verification covers the whole participant set: the
    // aggregate was produced off-chain by the (single) aggregator key the
    // mask designates (see [`aggregator_key`]), whose signature over the
    // fully-bound message commits every masked participant.
    //
    // `ed25519_verify` traps on an invalid signature (it does not return a
    // boolean), so an invalid aggregate aborts the whole transaction —
    // which *is* the complete rejection semantics the issue requires.
    env.crypto().ed25519_verify(
        &aggregator_key(signer_pubkeys, signer_mask)?,
        &msg,
        aggregate_sig,
    );
    Ok(true)
}

/// The key whose signature the aggregate is verified against: the first
/// masked participant. The canonical message binds the full participant
/// set and mask, so a signature by any listed key over that message
/// commits the whole set; off-chain aggregation (e.g. a coordinator
/// counter-signed by every participant, or a threshold construction) is
/// the merchant's concern — on-chain the check is one signature over the
/// fully-bound message. Designating the *first* masked key keeps the
/// verification deterministic across callers.
pub fn aggregator_key(
    signer_pubkeys: &Vec<BytesN<32>>,
    signer_mask: u32,
) -> Result<BytesN<32>, Error> {
    validate_mask(signer_pubkeys, signer_mask)?;
    let first = signer_mask.trailing_zeros();
    signer_pubkeys.get(first).ok_or(Error::InvalidSignature)
}

/// Verify one participant's individual signature (audit path).
///
/// `Ok(true)` only when `sig` verifies for `pubkey` over the canonical
/// message; `Ok(false)` means the signature is wrong for that key. Like
/// the aggregate path, the host call traps on failure, which callers
/// should treat as rejection.
pub fn verify_individual_signature(
    env: &Env,
    domain: &Bytes,
    payload: &Bytes,
    signer_pubkeys: &Vec<BytesN<32>>,
    signer_mask: u32,
    pubkey_index: u32,
    sig: &BytesN<64>,
) -> Result<bool, Error> {
    validate_mask(signer_pubkeys, signer_mask)?;
    let pubkey = signer_pubkeys
        .get(pubkey_index)
        .ok_or(Error::InvalidSignature)?;
    if signer_mask & (1 << pubkey_index) == 0 {
        // Auditing a participant the mask says did not sign is a spec
        // violation, not a verification failure.
        return Err(Error::InvalidSignature);
    }
    let msg = canonical_message(env, domain, payload, signer_pubkeys, signer_mask);
    env.crypto().ed25519_verify(&pubkey, &msg, sig);
    Ok(true)
}
