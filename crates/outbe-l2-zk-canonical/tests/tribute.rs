//! Frozen vectors for the tribute claim.
//!
//! These are consensus preimages: every party that folds a claim — a prover,
//! a verifier, the chain — folds them, so a change here is a change to what
//! verifies on L1. If one of these
//! asserts fails, the fix is to put the preimage back, not to update the bytes.

use alloy_primitives::{hex, B256};
use outbe_l2_zk_canonical::claims::tribute::{binding, TributeDraftClaim};
use outbe_zk_core::codec::{field_to_be_bytes, fits_in_fr, FR_MODULUS};
use outbe_zk_core::entity::Entity;
use outbe_zk_core::Error;

/// A `B256` holding the small field value `n`.
fn b256(n: u64) -> B256 {
    B256::from(alloy_primitives::U256::from(n))
}

fn sample(su_ids: Vec<B256>) -> TributeDraftClaim {
    TributeDraftClaim {
        id: b256(1),
        owner: b256(2),
        worldwide_day: 20_260_802,
        currency: 840,
        base: 100,
        micro: 0,
        su_ids,
    }
}

/// The fold order is `pos`, not declaration order, and `su_ids` folds as a
/// length-prefixed set. One assert catches a reordered `pos`, a dropped field
/// and a changed su-set encoding.
///
/// ```text
/// iterate(id, [owner, worldwide_day, currency, base, micro, 2, su_0, su_1])
/// ```
#[test]
fn entity_hash_keeps_the_frozen_fold_order() {
    let hash = sample(vec![b256(3), b256(4)]).entity_hash().unwrap();
    assert_eq!(
        field_to_be_bytes(&hash),
        hex::decode("20fa811a8b272be2f39466daa3dbe1215832c7b6f3ac98d6672e6f137c1f831c").unwrap()
    );
}

/// The set's length prefix is the easiest thing to lose in a rewrite: with no
/// su ids the body is still seven elements long, the last being `0`.
#[test]
fn entity_hash_keeps_the_empty_set_length_prefix() {
    let hash = sample(Vec::new()).entity_hash().unwrap();
    assert_eq!(
        field_to_be_bytes(&hash),
        hex::decode("1788c66be8733c9bd4c61b2f0398e6b9544fd0da373a5022310c3726ecbc1779").unwrap()
    );
}

/// `su_ids` is a canonical set: unsorted or duplicated input is rejected, not
/// silently normalised.
#[test]
fn entity_hash_rejects_an_unsorted_su_set() {
    let err = sample(vec![b256(4), b256(3)]).entity_hash().unwrap_err();
    assert!(matches!(err, Error::UnsortedSet(_)), "{err}");
}

/// `binding` folds `BINDING_DOMAIN = 1` first and keeps the
/// sender / draft_lo / draft_hi / host_chain_id / l2_chain_id order. Do not
/// touch these bytes.
#[test]
fn binding_keeps_the_frozen_vector() {
    let hash = binding(&[1; 20], &[2; 32], 19_280_501, 57005).unwrap();
    assert_eq!(
        field_to_be_bytes(&hash),
        hex::decode("1fa0a96020985973a74705b5e7b6f54f3c3f9b9ca1d0de200c93566e2eb73402").unwrap()
    );
}

/// The whole point of the sixth element: the same draft, caller and host chain
/// bind differently under a different L2.
#[test]
fn binding_separates_l2_chains() {
    assert_ne!(
        binding(&[1; 20], &[2; 32], 19_280_501, 57005).unwrap(),
        binding(&[1; 20], &[2; 32], 19_280_501, 57006).unwrap(),
    );
}

/// A `B256` at or above the modulus has no canonical element. It must fail the
/// fold rather than be reduced onto a different one — an aliased draft id would
/// break the on-chain/in-circuit binding.
#[test]
fn a_non_canonical_b256_is_rejected_not_reduced() {
    let modulus = B256::from(FR_MODULUS);
    assert!(!fits_in_fr(&modulus));
    assert!(fits_in_fr(&b256(2)));

    for claim in [
        TributeDraftClaim {
            id: modulus,
            ..sample(vec![b256(3)])
        },
        TributeDraftClaim {
            owner: modulus,
            ..sample(vec![b256(3)])
        },
        TributeDraftClaim {
            su_ids: vec![modulus],
            ..sample(Vec::new())
        },
    ] {
        let err = claim.entity_hash().unwrap_err();
        assert!(matches!(err, Error::NonCanonical("bytes32")), "{err}");
    }
}

/// A consumer that never verifies a proof takes this crate with
/// `default-features = false`: it needs the claim half and not the key table.
/// Both halves of that are checked here, in the file that compiles with and
/// without `l2-keys`:
///
/// * the core is reached through the re-export, the way such a consumer reaches
///   it, not through a second `outbe-zk-core` entry in its manifest;
/// * everything touched is registry-free, so `--no-default-features` builds it.
///
/// If the feature gate ever creeps over the claim, `cargo test
/// -p outbe-l2-zk-canonical --no-default-features` stops compiling here.
#[test]
fn the_enclaves_half_needs_no_registry() {
    use outbe_l2_zk_canonical::claims::tribute::{public_words, PublicInputs, PUBLIC_INPUT_COUNT};
    use outbe_l2_zk_canonical::outbe_zk_core as zk_core;

    let claim = sample(vec![b256(3)]);
    let nft_hash = claim.entity_hash().unwrap();
    let binding_hash = binding(&[1; 20], &claim.id.0, 19_280_501, 57005).unwrap();

    // The generated public-input type and its ABI order are part of the claim,
    // not of the key table: a prover needs them with no registry compiled in.
    let public = PublicInputs {
        owner: zk_core::codec::field_from_be_bytes(claim.owner.as_slice()),
        nft_hash,
        binding_hash,
        merkle_root: nft_hash,
    };
    assert_eq!(public_words(&public).len(), PUBLIC_INPUT_COUNT);
    assert_eq!(public_words(&public)[1], nft_hash);

    assert_eq!(field_to_be_bytes(&nft_hash).len(), 32);
    assert!(zk_core::codec::fits_in_fr(&claim.owner));
}
