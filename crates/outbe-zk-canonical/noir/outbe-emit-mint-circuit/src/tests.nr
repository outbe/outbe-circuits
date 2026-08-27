use super::{
    emit::{change_key, merkle_root, note_commitment, note_sn, nullifier, EMIT_DOMAIN, TAG_EMPTY},
    main,
    MERKLE_DEPTH,
};
use outbe_circuit_core::{hash, inclusion::compute_merkle_root};
use outbe_circuit_core::types::EthAddress;

pub fn empty_leaf(chain_id: u64) -> Field {
    hash::hash_multi(TAG_EMPTY, [chain_id as Field])
}

fn single_leaf_path(chain_id: u64) -> [Field; MERKLE_DEPTH] {
    let mut path = [0; MERKLE_DEPTH];
    path[0] = empty_leaf(chain_id);
    for level in 1..MERKLE_DEPTH {
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
    let n = nullifier(chain_id, serial, key);
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
    let root = compute_merkle_root(
        EMIT_DOMAIN + 1,
        commitment,
        path,
        [true; MERKLE_DEPTH],
    );
    let n = nullifier(chain_id, serial, key);
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
    let n = nullifier(chain_id, serial, key);
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
    let n = nullifier(chain_id, wrong_serial, key);
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
    let n = nullifier(chain_id, serial, key);
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
    let n = nullifier(chain_id, serial, key);
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
    let n = nullifier(chain_id, serial, key);
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
    let wrong_n = nullifier(chain_id, serial, key) + 1;
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
    let n = nullifier(chain_id, serial, key);
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
    let n = nullifier(chain_id, serial, key);
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
    let n = nullifier(chain_id, serial, key);
    main(chain_id, root, n, owner, 40, 0, 100, key, 0, path);
}

#[test(should_fail)]
fn leaf_index_above_tree_capacity_fails() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(chain_id, serial, key);
    main(chain_id, root, n, owner, 100, 0, 100, key, 0x100000, path);
}

/// The `[u8; 20]` ABI param used to bound the owner at 160 bits for free. Now
/// that it crosses the ABI as a bare `Field`, `EthAddress::from_field` is the
/// only thing holding that bound — check it actually bites.
#[test(should_fail)]
fn owner_above_160_bits_fails() {
    let _ = EthAddress::from_field(0x010000000000000000000000000000000000000000);
}
