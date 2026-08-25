use super::{
    emit::{change_key, empty_leaf, merkle_root, note_commitment, note_sn, nullifier},
    main,
    MERKLE_DEPTH,
};
use outbe_circuit_core::hash2;

fn single_leaf_path(chain_id: u64) -> [Field; MERKLE_DEPTH] {
    let mut path = [0; MERKLE_DEPTH];
    path[0] = empty_leaf(chain_id);
    for level in 1..MERKLE_DEPTH {
        path[level] = hash2::hash_2([path[level - 1], path[level - 1]]);
    }
    path
}

#[test]
fn full_mint_uses_zero_change_sentinel() {
    let chain_id = 31337;
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let bits = [false; MERKLE_DEPTH];
    let root = merkle_root(commitment, path, bits);
    let n = nullifier(chain_id, serial, key);
    main(chain_id, root, n, owner, 100, 0, 100, key, bits, path);
}

#[test]
fn partial_mint_rotates_change_key() {
    let chain_id = 31337;
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let bits = [false; MERKLE_DEPTH];
    let root = merkle_root(commitment, path, bits);
    let n = nullifier(chain_id, serial, key);
    let next_key = change_key(key, n);
    let change = note_commitment(chain_id, note_sn(owner, next_key), 60);
    main(chain_id, root, n, owner, 40, change, 100, key, bits, path);
}

#[test(should_fail)]
fn zero_key_fails() {
    let chain_id = 31337;
    let owner = [0x22; 20];
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
        [false; MERKLE_DEPTH],
        path,
    );
}

#[test(should_fail)]
fn wrong_owner_fails_membership() {
    let chain_id = 31337;
    let owner = [0x22; 20];
    let wrong_owner = [0x23; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let bits = [false; MERKLE_DEPTH];
    let root = merkle_root(commitment, path, bits);
    let wrong_serial = note_sn(wrong_owner, key);
    let n = nullifier(chain_id, wrong_serial, key);
    main(chain_id, root, n, wrong_owner, 100, 0, 100, key, bits, path);
}

#[test(should_fail)]
fn wrong_private_key_fails_membership() {
    let chain_id = 31337;
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let bits = [false; MERKLE_DEPTH];
    let root = merkle_root(commitment, path, bits);
    let n = nullifier(chain_id, serial, key);
    main(chain_id, root, n, owner, 100, 0, 100, 18, bits, path);
}

#[test(should_fail)]
fn wrong_path_fails_membership() {
    let chain_id = 31337;
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let bits = [false; MERKLE_DEPTH];
    let root = merkle_root(commitment, path, bits);
    let n = nullifier(chain_id, serial, key);
    let mut wrong_path = path;
    wrong_path[0] = 0;
    main(chain_id, root, n, owner, 100, 0, 100, key, bits, wrong_path);
}

#[test(should_fail)]
fn wrong_path_bits_fail_membership() {
    let chain_id = 31337;
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let bits = [false; MERKLE_DEPTH];
    let root = merkle_root(commitment, path, bits);
    let n = nullifier(chain_id, serial, key);
    let mut wrong_bits = bits;
    wrong_bits[0] = true;
    main(chain_id, root, n, owner, 100, 0, 100, key, wrong_bits, path);
}

#[test(should_fail)]
fn wrong_nullifier_fails() {
    let chain_id = 31337;
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let bits = [false; MERKLE_DEPTH];
    let root = merkle_root(commitment, path, bits);
    let wrong_n = nullifier(chain_id, serial, key) + 1;
    main(chain_id, root, wrong_n, owner, 100, 0, 100, key, bits, path);
}

#[test(should_fail)]
fn wrong_change_amount_fails() {
    let chain_id = 31337;
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let bits = [false; MERKLE_DEPTH];
    let root = merkle_root(commitment, path, bits);
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
        bits,
        path,
    );
}

#[test(should_fail)]
fn full_mint_rejects_nonzero_change_sentinel() {
    let chain_id = 31337;
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let bits = [false; MERKLE_DEPTH];
    let root = merkle_root(commitment, path, bits);
    let n = nullifier(chain_id, serial, key);
    main(chain_id, root, n, owner, 100, 1, 100, key, bits, path);
}

#[test(should_fail)]
fn partial_mint_rejects_zero_change_commitment() {
    let chain_id = 31337;
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let path = single_leaf_path(chain_id);
    let bits = [false; MERKLE_DEPTH];
    let root = merkle_root(commitment, path, bits);
    let n = nullifier(chain_id, serial, key);
    main(chain_id, root, n, owner, 40, 0, 100, key, bits, path);
}
