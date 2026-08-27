use super::{
    emit::{
        change_key, merkle_root, note_commitment, note_sn, nullifier, EMIT_DOMAIN,
        OUTBE_CHANGE_KEY, OUTBE_COMMITMENT, OUTBE_EMPTY, OUTBE_NOTE_SN, OUTBE_NULLIFIER,
    },
    main,
};
use outbe_circuit_core::{hash, merkle_tree::{merkle_root_from_indices, DEPTH}};
use outbe_circuit_core::types::EthAddress;

pub fn empty_leaf(chain_id: u64) -> Field {
    hash::hash_multi(OUTBE_EMPTY, [chain_id as Field])
}

fn single_leaf_path(chain_id: u64) -> [Field; DEPTH] {
    let mut path = [0; DEPTH];
    path[0] = empty_leaf(chain_id);
    for level in 1..DEPTH {
        path[level] = hash::hash_3([EMIT_DOMAIN, path[level - 1], path[level - 1]]);
    }
    path
}

#[test]
fn full_mint_uses_zero_change_sentinel() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    main(chain_id, root, n, owner, 100, 0, 100, key, 0, path);
}

#[test(should_fail)]
fn wrong_tree_domain_fails_membership() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root_from_indices(EMIT_DOMAIN + 1, commitment, path, [true; DEPTH]);
    let n = nullifier(commitment, key);
    main(chain_id, root, n, owner, 100, 0, 100, key, 0, path);
}

#[test]
fn partial_mint_rotates_change_key() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    let next_key = change_key(key, n);
    let change = note_commitment(chain_id, note_sn(owner, next_key), 60);
    main(chain_id, root, n, owner, 40, change, 100, key, 0, path);
}

#[test(should_fail)]
fn zero_key_fails() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let path = single_leaf_path(chain_id);
    main(
        chain_id,
        1,
        1,
        owner,
        1,
        0,
        1,
        0,
        0,
        path,
    );
}

#[test(should_fail)]
fn wrong_owner_fails_membership() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let wrong_owner = EthAddress::from_field(0x2323232323232323232323232323232323232323);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let wrong_serial = note_sn(wrong_owner, key);
    let wrong_commitment = note_commitment(chain_id, wrong_serial, 100);
    let n = nullifier(wrong_commitment, key);
    main(chain_id, root, n, wrong_owner, 100, 0, 100, key, 0, path);
}

#[test(should_fail)]
fn wrong_private_key_fails_membership() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    main(chain_id, root, n, owner, 100, 0, 100, 18, 0, path);
}

#[test(should_fail)]
fn wrong_path_fails_membership() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    let mut wrong_path = path;
    wrong_path[0] = 0;
    main(chain_id, root, n, owner, 100, 0, 100, key, 0, wrong_path);
}

#[test(should_fail)]
fn wrong_leaf_index_fails_membership() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    main(chain_id, root, n, owner, 100, 0, 100, key, 1, path);
}

#[test(should_fail)]
fn wrong_nullifier_fails() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let wrong_n = nullifier(commitment, key) + 1;
    main(chain_id, root, wrong_n, owner, 100, 0, 100, key, 0, path);
}

#[test(should_fail)]
fn wrong_change_amount_fails() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    let next_key = change_key(key, n);
    let wrong_change = note_commitment(chain_id, note_sn(owner, next_key), 60);
    main(
        chain_id,
        root,
        n,
        owner,
        41,
        wrong_change,
        100,
        key,
        0,
        path,
    );
}

#[test(should_fail)]
fn full_mint_rejects_nonzero_change_sentinel() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    main(chain_id, root, n, owner, 100, 1, 100, key, 0, path);
}

#[test(should_fail)]
fn partial_mint_rejects_zero_change_commitment() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    main(chain_id, root, n, owner, 40, 0, 100, key, 0, path);
}

// `leaf_index_above_tree_capacity_fails` lived here. At DEPTH = 32 the tree holds
// 2^32 leaves and `main` takes `leaf_index: u32`, so no over-capacity index is
// constructible -- the ABI type is the bound. The generic check that a too-wide
// index cannot resolve a root lives in `outbe_circuit_core::merkle_tree`.

/// The `[u8; 20]` ABI param used to bound the owner at 160 bits for free. Now
/// that it crosses the ABI as a bare `Field`, `EthAddress::from_field` is the
/// only thing holding that bound — check it actually bites.
#[test(should_fail)]
fn owner_above_160_bits_fails() {
    let _ = EthAddress::from_field(0x010000000000000000000000000000000000000000);
}

// Adversarial constraints: each witness is otherwise valid.

#[test(should_fail)]
fn overspend_above_note_amount_fails() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    main(chain_id, root, n, owner, 101, 0, 100, key, 0, path);
}

#[test(should_fail)]
fn zero_mint_units_fails() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    let next_key = change_key(key, n);
    let equal_value_change = note_commitment(chain_id, note_sn(owner, next_key), 100);
    main(
        chain_id,
        root,
        n,
        owner,
        0,
        equal_value_change,
        100,
        key,
        0,
        path,
    );
}

#[test(should_fail)]
fn zero_nullifier_public_input_fails() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    main(chain_id, root, 0, owner, 100, 0, 100, key, 0, path);
}

#[test(should_fail)]
fn tampered_public_root_fails_membership() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    main(chain_id, root + 1, n, owner, 100, 0, 100, key, 0, path);
}

#[test(should_fail)]
fn cross_chain_replay_fails_with_recomputed_nullifier() {
    let source_chain = 31337;
    let target_chain = 1;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let source_commitment = note_commitment(source_chain, serial, 100);
    let path = single_leaf_path(source_chain);
    let source_root = merkle_root(source_commitment, 0, path);
    let target_commitment = note_commitment(target_chain, serial, 100);
    let target_nullifier = nullifier(target_commitment, key);
    main(
        target_chain,
        source_root,
        target_nullifier,
        owner,
        100,
        0,
        100,
        key,
        0,
        path,
    );
}

#[test(should_fail)]
fn larger_hidden_amount_cannot_spend_smaller_note() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let committed_amount = 100;
    let forged_amount = 101;
    let commitment = note_commitment(chain_id, serial, committed_amount);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let forged_commitment = note_commitment(chain_id, serial, forged_amount);
    let forged_nullifier = nullifier(forged_commitment, key);
    main(
        chain_id,
        root,
        forged_nullifier,
        owner,
        forged_amount,
        0,
        forged_amount,
        key,
        0,
        path,
    );
}

#[test(should_fail)]
fn partial_mint_rejects_unrotated_change_key() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    let unrotated_change = note_commitment(chain_id, serial, 60);
    main(
        chain_id,
        root,
        n,
        owner,
        40,
        unrotated_change,
        100,
        key,
        0,
        path,
    );
}

#[test(should_fail)]
fn partial_mint_rejects_change_for_another_owner() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let other_owner = EthAddress::from_field(0x9999999999999999999999999999999999999999);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    let next_key = change_key(key, n);
    let redirected_change = note_commitment(chain_id, note_sn(other_owner, next_key), 60);
    main(
        chain_id,
        root,
        n,
        owner,
        40,
        redirected_change,
        100,
        key,
        0,
        path,
    );
}

// Trust boundaries: these relations are valid in-circuit and require runtime policy.

#[test]
fn duplicate_leaf_proves_at_two_indices_runtime_must_dedup() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let mut path = single_leaf_path(chain_id);
    path[0] = commitment;
    let root = merkle_root(commitment, 0, path);
    assert_eq(root, merkle_root(commitment, 1, path));
    let n = nullifier(commitment, key);
    main(chain_id, root, n, owner, 100, 0, 100, key, 0, path);
    main(chain_id, root, n, owner, 100, 0, 100, key, 1, path);
}

#[test]
fn same_note_proves_under_two_roots_runtime_must_pin_roots() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let n = nullifier(commitment, key);
    let path_a = single_leaf_path(chain_id);
    let root_a = merkle_root(commitment, 0, path_a);
    let mut path_b = single_leaf_path(chain_id);
    path_b[0] = empty_leaf(chain_id);
    let root_b = merkle_root(commitment, 1, path_b);
    assert(root_a != root_b);
    main(chain_id, root_a, n, owner, 100, 0, 100, key, 0, path_a);
    main(chain_id, root_b, n, owner, 100, 0, 100, key, 1, path_b);
}

#[test]
fn max_leaf_index_boundary_proves() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let last = 0xffffffff;
    let root = merkle_root(commitment, last, path);
    let n = nullifier(commitment, key);
    main(chain_id, root, n, owner, 100, 0, 100, key, last, path);
}

#[test]
fn same_key_distinct_notes_have_independent_nullifiers() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment_40 = note_commitment(chain_id, serial, 40);
    let commitment_60 = note_commitment(chain_id, serial, 60);
    let nullifier_40 = nullifier(commitment_40, key);
    let nullifier_60 = nullifier(commitment_60, key);
    assert(nullifier_40 != nullifier_60);

    let path_40 = single_leaf_path(chain_id);
    let root_40 = merkle_root(commitment_40, 0, path_40);
    main(
        chain_id,
        root_40,
        nullifier_40,
        owner,
        40,
        0,
        40,
        key,
        0,
        path_40,
    );

    let path_60 = single_leaf_path(chain_id);
    let root_60 = merkle_root(commitment_60, 0, path_60);
    main(
        chain_id,
        root_60,
        nullifier_60,
        owner,
        60,
        0,
        60,
        key,
        0,
        path_60,
    );
}

#[test]
fn zero_chain_id_and_zero_owner_are_accepted_runtime_must_bind_them() {
    let chain_id = 0;
    let owner = EthAddress::from_field(0);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 5);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    main(chain_id, root, n, owner, 5, 0, 5, key, 0, path);
}

#[test]
fn protocol_tags_are_pairwise_distinct() {
    let tags = [
        EMIT_DOMAIN,
        OUTBE_NOTE_SN,
        OUTBE_COMMITMENT,
        OUTBE_NULLIFIER,
        OUTBE_CHANGE_KEY,
        OUTBE_EMPTY,
    ];
    for i in 0..tags.len() {
        assert(tags[i] != 0);
        for j in (i + 1)..tags.len() {
            assert(tags[i] != tags[j]);
        }
    }
}

#[test]
fn sampled_key_rotations_avoid_spent_identity() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let keys = [0, 1, 2, 17, EMIT_DOMAIN, OUTBE_CHANGE_KEY];
    for key in keys {
        let serial = note_sn(owner, key);
        let commitment = note_commitment(chain_id, serial, 100);
        let n = nullifier(commitment, key);
        let next_key = change_key(key, n);
        let next_serial = note_sn(owner, next_key);
        let next_commitment = note_commitment(chain_id, next_serial, 60);
        let next_nullifier = nullifier(next_commitment, next_key);
        assert(next_key != key);
        assert(next_serial != serial);
        assert(next_nullifier != n);
    }
}

#[test]
fn change_note_is_spendable_after_rotation() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    let next_key = change_key(key, n);
    let next_serial = note_sn(owner, next_key);
    let change = note_commitment(chain_id, next_serial, 60);
    main(chain_id, root, n, owner, 40, change, 100, key, 0, path);

    let change_path = single_leaf_path(chain_id);
    let change_root = merkle_root(change, 0, change_path);
    let change_nullifier = nullifier(change, next_key);
    main(
        chain_id,
        change_root,
        change_nullifier,
        owner,
        60,
        0,
        60,
        next_key,
        0,
        change_path,
    );
}

#[test]
fn u128_max_amounts_full_and_partial_mint() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let max: u128 = 340282366920938463463374607431768211455;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, max);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(commitment, key);
    main(chain_id, root, n, owner, max, 0, max, key, 0, path);

    let next_key = change_key(key, n);
    let change = note_commitment(chain_id, note_sn(owner, next_key), max - 1);
    main(chain_id, root, n, owner, 1, change, max, key, 0, path);
}
