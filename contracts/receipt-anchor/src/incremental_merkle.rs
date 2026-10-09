//! Append-only incremental Merkle tree for continuous receipt anchoring
//! (issue #424).
//!
//! Instead of anchoring a precomputed batch root, a merchant can append
//! receipt leaves one at a time. The contract keeps only the tree's
//! *frontier* — for every set bit `i` of the leaf count, the root of the
//! complete left subtree of `2^i` leaves at level `i` — so an insertion
//! costs at most `depth` hashes and one storage write, and the root is
//! derived from at most `depth` more hashes. No leaf is ever re-read.
//!
//! The tree follows exactly the batch conventions of `ReceiptAnchor` and the
//! TypeScript SDK (`merkle-vectors.json`, ADR-001): sorted-pair SHA-256, and
//! at every level with an odd node count the final node is paired with
//! itself. The root of `n` inserted leaves is therefore byte-identical to the
//! batch root of the same `n` leaves, and existing batch proofs verify
//! against it.
//!
//! Storage: one instance entry holding the leaf count, the current root and
//! the frontier packed into a single `Bytes` blob (32 bytes per level,
//! slot `i` at offset `32 * i`) — no per-node keys, no `Vec` element
//! headers.

use nexus-vault_common::Error;
use sha2::{Digest, Sha256};
use soroban_sdk::{contracttype, Bytes, BytesN, Env};

/// Maximum supported tree depth.
pub const MAX_DEPTH: u32 = 32;

/// Maximum number of leaves: a full tree of depth [`MAX_DEPTH`]
/// (4,294,967,296 receipts).
pub const MAX_LEAVES: u64 = 1u64 << MAX_DEPTH;

/// Persisted incremental tree state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncrementalTree {
    /// Number of leaves inserted so far.
    pub count: u64,
    /// Root over the `count` leaves inserted so far.
    pub root: BytesN<32>,
    /// Packed frontier: slot `i` (bytes `32*i .. 32*i + 32`) is the latest
    /// complete subtree root at level `i`. Only slots whose bit is set in
    /// `count` are meaningful.
    pub frontier: Bytes,
}

/// Sorted-pair SHA-256, identical to `ReceiptAnchor::fold_proof`.
pub fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = Sha256::new();
    hasher.update(lo);
    hasher.update(hi);
    hasher.finalize().into()
}

fn slot(frontier: &Bytes, level: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    frontier
        .slice(level * 32..level * 32 + 32)
        .copy_into_slice(&mut out);
    out
}

fn set_slot(frontier: &mut Bytes, level: u32, node: &[u8; 32]) {
    let start = level * 32;
    if frontier.len() == start {
        frontier.extend_from_array(node);
    } else {
        for (i, byte) in node.iter().enumerate() {
            frontier.set(start + i as u32, *byte);
        }
    }
}

/// Root of a non-empty tree of `count` leaves described by `frontier`.
fn compute_root(frontier: &Bytes, count: u64) -> [u8; 32] {
    // `partial` is the right-most, incomplete node at the current level (if
    // any): the fold of every leaf past the last complete subtree.
    let mut partial: Option<[u8; 32]> = None;
    let mut level = 0u32;
    loop {
        // Number of nodes at this level: ceil(count / 2^level).
        let nodes = ((count - 1) >> level) + 1;
        let bit_set = (count >> level) & 1 == 1;
        if nodes == 1 {
            return partial.unwrap_or_else(|| slot(frontier, level));
        }
        partial = match (partial, bit_set) {
            // Partial node has an odd index: its left sibling is the
            // frontier subtree.
            (Some(p), true) => Some(hash_pair(&slot(frontier, level), &p)),
            // Partial node is last with an even index: pair with itself.
            (Some(p), false) => Some(hash_pair(&p, &p)),
            // Odd count of complete nodes: the last one pairs with itself.
            (None, true) => {
                let s = slot(frontier, level);
                Some(hash_pair(&s, &s))
            }
            // Even count of complete nodes: everything pairs up.
            (None, false) => None,
        };
        level += 1;
    }
}

/// Append `leaf` to `tree`, updating the frontier and root in place.
/// Returns the zero-based index of the inserted leaf.
pub fn insert(tree: &mut IncrementalTree, env: &Env, leaf: &BytesN<32>) -> Result<u64, Error> {
    if tree.count >= MAX_LEAVES {
        return Err(Error::BatchTooLarge);
    }
    let index = tree.count;

    // Carry the new leaf up through every complete subtree it closes.
    let mut node = leaf.to_array();
    let mut level = 0u32;
    while (index >> level) & 1 == 1 {
        node = hash_pair(&slot(&tree.frontier, level), &node);
        level += 1;
    }
    set_slot(&mut tree.frontier, level, &node);

    tree.count = index + 1;
    tree.root = BytesN::from_array(env, &compute_root(&tree.frontier, tree.count));
    Ok(index)
}

/// An empty tree (no leaves; `root` is all zeroes until the first insert).
pub fn empty(env: &Env) -> IncrementalTree {
    IncrementalTree {
        count: 0,
        root: BytesN::from_array(env, &[0u8; 32]),
        frontier: Bytes::new(env),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    fn sha(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    /// Reference batch builder: the SDK's `buildRoot` (duplicate the last
    /// node at every odd level).
    fn batch_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
        }
        level[0]
    }

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| sha(&(i as u64).to_le_bytes())).collect()
    }

    #[test]
    fn matches_batch_root_for_every_size() {
        let env = Env::default();
        let all = leaves(130);
        let mut tree = empty(&env);
        for (i, leaf) in all.iter().enumerate() {
            let idx = insert(&mut tree, &env, &BytesN::from_array(&env, leaf)).unwrap();
            assert_eq!(idx, i as u64);
            assert_eq!(
                tree.root.to_array(),
                batch_root(&all[..=i]),
                "root mismatch at {} leaves",
                i + 1
            );
        }
    }

    #[test]
    fn matches_canonical_sdk_vector() {
        // `five-leaf batch` in merkle-vectors.json: leaves are
        // sha256("nexus-vault-edge-5-{i}").
        let env = Env::default();
        let mut tree = empty(&env);
        for i in 0..5 {
            let leaf = sha(std::format!("nexus-vault-edge-5-{i}").as_bytes());
            insert(&mut tree, &env, &BytesN::from_array(&env, &leaf)).unwrap();
        }
        let expected: [u8; 32] = [
            0x10, 0xef, 0x69, 0x1d, 0xb1, 0xdb, 0xc4, 0x9b, 0x95, 0xf3, 0x8f, 0xee, 0xf2, 0x01,
            0xfa, 0x5d, 0x26, 0xec, 0x7e, 0xf8, 0x51, 0xfc, 0x81, 0x8c, 0x04, 0x1f, 0xbd, 0x6c,
            0x8a, 0x83, 0x46, 0xf1,
        ];
        assert_eq!(tree.root.to_array(), expected);
    }

    #[test]
    fn frontier_stays_logarithmic() {
        let env = Env::default();
        let mut tree = empty(&env);
        for leaf in leaves(1024) {
            insert(&mut tree, &env, &BytesN::from_array(&env, &leaf)).unwrap();
        }
        // 1024 = 2^10: eleven levels (0..=10) ever used.
        assert_eq!(tree.frontier.len(), 11 * 32);
    }

    #[test]
    fn supports_depth_thirty_two() {
        // Jump to one leaf short of a full depth-32 tree: every lower level
        // holds a complete subtree, so the last insert carries all the way
        // up to level 32.
        let env = Env::default();
        let mut frontier = Bytes::new(&env);
        let mut full = sha(b"leaf");
        for _ in 0..MAX_DEPTH {
            frontier.extend_from_array(&full);
            full = hash_pair(&full, &full);
        }
        let mut tree = IncrementalTree {
            count: MAX_LEAVES - 1,
            root: BytesN::from_array(&env, &[0u8; 32]),
            frontier,
        };
        let idx = insert(&mut tree, &env, &BytesN::from_array(&env, &sha(b"leaf"))).unwrap();
        assert_eq!(idx, MAX_LEAVES - 1);
        assert_eq!(tree.count, MAX_LEAVES);
        // 2^32 identical leaves: the root is the leaf hashed with itself 32 times.
        assert_eq!(tree.root.to_array(), full);
        assert_eq!(
            insert(&mut tree, &env, &BytesN::from_array(&env, &sha(b"x"))),
            Err(Error::BatchTooLarge)
        );
    }
}

#[cfg(test)]
mod contract_tests {
    use crate::{ReceiptAnchor, ReceiptAnchorClient};
    use nexus-vault_common::Error;
    use soroban_sdk::{
        testutils::{Address as _, Events as _},
        vec, Address, BytesN, Env, IntoVal, Map, Symbol, Val,
    };

    fn setup() -> (Env, ReceiptAnchorClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register(ReceiptAnchor, ());
        let client = ReceiptAnchorClient::new(&env, &id);
        let merchant = Address::generate(&env);
        // The shard wasm hash is only used by batch anchoring.
        client.initialize(&merchant, &BytesN::from_array(&env, &[0u8; 32]));
        (env, client)
    }

    fn leaf(env: &Env, n: u8) -> BytesN<32> {
        BytesN::from_array(env, &[n; 32])
    }

    #[test]
    fn insert_returns_sequential_indices_and_tracks_root() {
        let (env, client) = setup();
        assert_eq!(client.get_incremental_leaf_count(), 0);
        assert_eq!(
            client.try_get_incremental_root(),
            Err(Ok(Error::RootNotFound))
        );

        assert_eq!(client.insert_receipt_leaf(&leaf(&env, 1)), 0);
        // A single-leaf tree's root is the leaf itself.
        assert_eq!(client.get_incremental_root(), leaf(&env, 1));

        assert_eq!(client.insert_receipt_leaf(&leaf(&env, 2)), 1);
        assert_eq!(client.insert_receipt_leaf(&leaf(&env, 3)), 2);
        assert_eq!(client.get_incremental_leaf_count(), 3);
    }

    #[test]
    fn batch_proof_verifies_against_incremental_root() {
        let (env, client) = setup();
        let (a, b, c) = (leaf(&env, 1), leaf(&env, 2), leaf(&env, 3));
        for l in [&a, &b, &c] {
            client.insert_receipt_leaf(l);
        }

        // Three leaves: root = H(H(a, b), H(c, c)). Proof for `c` is [c, H(a, b)].
        let ab = super::hash_pair(&a.to_array(), &b.to_array());
        let cc = super::hash_pair(&c.to_array(), &c.to_array());
        let expected = super::hash_pair(&ab, &cc);
        assert_eq!(client.get_incremental_root().to_array(), expected);

        let proof = vec![&env, c.clone(), BytesN::from_array(&env, &ab)];
        let mut folded = c.to_array();
        for sibling in proof.iter() {
            folded = super::hash_pair(&folded, &sibling.to_array());
        }
        assert_eq!(folded, expected);
    }

    #[test]
    fn insert_emits_event() {
        let (env, client) = setup();
        client.insert_receipt_leaf(&leaf(&env, 7));

        let mut data = Map::<Val, Val>::new(&env);
        data.set(
            Symbol::new(&env, "leaf").into_val(&env),
            leaf(&env, 7).into_val(&env),
        );
        data.set(
            Symbol::new(&env, "root").into_val(&env),
            leaf(&env, 7).into_val(&env),
        );
        assert_eq!(
            env.events().all().filter_by_contract(&client.address),
            vec![
                &env,
                (
                    client.address.clone(),
                    (Symbol::new(&env, "receipt_leaf_inserted_event"), 0u64).into_val(&env),
                    data.into_val(&env)
                )
            ]
        );
    }

    #[test]
    fn insert_requires_initialization() {
        let env = Env::default();
        env.mock_all_auths();
        let client = ReceiptAnchorClient::new(&env, &env.register(ReceiptAnchor, ()));
        assert_eq!(
            client.try_insert_receipt_leaf(&leaf(&env, 1)),
            Err(Ok(Error::NotInitialized))
        );
    }

    #[test]
    #[should_panic]
    fn insert_requires_merchant_auth() {
        let (env, client) = setup();
        env.set_auths(&[]);
        client.insert_receipt_leaf(&leaf(&env, 1));
    }
}
