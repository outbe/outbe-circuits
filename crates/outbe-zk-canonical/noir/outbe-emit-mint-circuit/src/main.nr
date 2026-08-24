use outbe_emit_circuit_core::{change_key, empty_leaf, merkle_root, node, note_commitment, note_sn, nullifier};

fn main(
    pool_id: pub Field,
    root: pub Field,
    nullifier: pub Field,
    note_owner: pub [u8; 20],
    mint_units: pub u64,
    change_commitment: pub Field,
    note_amount: u64,
    note_spend_key: Field,
    leaf_index: u32,
    auth_path: [Field; 20],
) {
    assert(mint_units > 0);
    assert(mint_units <= note_amount);
    assert(leaf_index < (1 << 20));
    assert(nullifier != 0);
    assert(note_spend_key != 0);

    let serial = note_sn(note_owner, note_spend_key);
    let commitment = note_commitment(pool_id, serial, note_amount);
    let computed_root = merkle_root(commitment, leaf_index, auth_path);
    let computed_nullifier = outbe_emit_circuit_core::nullifier(pool_id, serial, note_spend_key);

    assert(serial != 0);
    assert(commitment != 0);
    assert_eq(computed_root, root);
    assert_eq(computed_nullifier, nullifier);

    let remaining = note_amount - mint_units;
    let creates_change = remaining > 0;
    assert((change_commitment != 0) == creates_change);
    if creates_change {
        let next_key = change_key(note_spend_key, computed_nullifier);
        let next_serial = note_sn(note_owner, next_key);
        let next_commitment = note_commitment(pool_id, next_serial, remaining);
        let next_nullifier = outbe_emit_circuit_core::nullifier(pool_id, next_serial, next_key);
        assert(next_key != 0);
        assert(next_serial != 0);
        assert(next_commitment != 0);
        assert_eq(change_commitment, next_commitment);
        assert(next_nullifier != 0);
    }
}

fn single_leaf_path(pool_id: Field) -> [Field; 20] {
    let mut path = [0; 20];
    path[0] = empty_leaf(pool_id);
    for level in 1..20 {
        path[level] = node(level - 1, path[level - 1], path[level - 1]);
    }
    path
}

#[test]
fn full_mint_uses_zero_change_sentinel() {
    let pool = outbe_emit_circuit_core::pool_id(31337, 19);
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(pool, serial, 100);
    let path = single_leaf_path(pool);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(pool, serial, key);
    main(pool, root, n, owner, 100, 0, 100, key, 0, path);
}

#[test]
fn partial_mint_rotates_change_key() {
    let pool = outbe_emit_circuit_core::pool_id(31337, 19);
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(pool, serial, 100);
    let path = single_leaf_path(pool);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(pool, serial, key);
    let next_key = change_key(key, n);
    let change = note_commitment(pool, note_sn(owner, next_key), 60);
    main(pool, root, n, owner, 40, change, 100, key, 0, path);
}

#[test(should_fail)]
fn zero_key_fails() {
    let pool = outbe_emit_circuit_core::pool_id(31337, 19);
    let owner = [0x22; 20];
    let path = single_leaf_path(pool);
    main(pool, 1, 1, owner, 1, 0, 1, 0, 0, path);
}

#[test(should_fail)]
fn wrong_owner_fails_membership() {
    let pool = outbe_emit_circuit_core::pool_id(31337, 19);
    let owner = [0x22; 20];
    let wrong_owner = [0x23; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(pool, serial, 100);
    let path = single_leaf_path(pool);
    let root = merkle_root(commitment, 0, path);
    let wrong_serial = note_sn(wrong_owner, key);
    let n = nullifier(pool, wrong_serial, key);
    main(pool, root, n, wrong_owner, 100, 0, 100, key, 0, path);
}

#[test(should_fail)]
fn wrong_private_key_fails_membership() {
    let pool = outbe_emit_circuit_core::pool_id(31337, 19);
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(pool, serial, 100);
    let path = single_leaf_path(pool);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(pool, serial, key);
    main(pool, root, n, owner, 100, 0, 100, 18, 0, path);
}

#[test(should_fail)]
fn wrong_path_fails_membership() {
    let pool = outbe_emit_circuit_core::pool_id(31337, 19);
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(pool, serial, 100);
    let path = single_leaf_path(pool);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(pool, serial, key);
    let mut wrong_path = path;
    wrong_path[0] = 0;
    main(pool, root, n, owner, 100, 0, 100, key, 0, wrong_path);
}

#[test(should_fail)]
fn wrong_nullifier_fails() {
    let pool = outbe_emit_circuit_core::pool_id(31337, 19);
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(pool, serial, 100);
    let path = single_leaf_path(pool);
    let root = merkle_root(commitment, 0, path);
    let wrong_n = nullifier(pool, serial, key) + 1;
    main(pool, root, wrong_n, owner, 100, 0, 100, key, 0, path);
}

#[test(should_fail)]
fn wrong_change_amount_fails() {
    let pool = outbe_emit_circuit_core::pool_id(31337, 19);
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(pool, serial, 100);
    let path = single_leaf_path(pool);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(pool, serial, key);
    let next_key = change_key(key, n);
    let wrong_change = note_commitment(pool, note_sn(owner, next_key), 60);
    main(pool, root, n, owner, 41, wrong_change, 100, key, 0, path);
}

#[test(should_fail)]
fn full_mint_rejects_nonzero_change_sentinel() {
    let pool = outbe_emit_circuit_core::pool_id(31337, 19);
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(pool, serial, 100);
    let path = single_leaf_path(pool);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(pool, serial, key);
    main(pool, root, n, owner, 100, 1, 100, key, 0, path);
}

#[test(should_fail)]
fn partial_mint_rejects_zero_change_commitment() {
    let pool = outbe_emit_circuit_core::pool_id(31337, 19);
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(pool, serial, 100);
    let path = single_leaf_path(pool);
    let root = merkle_root(commitment, 0, path);
    let n = nullifier(pool, serial, key);
    main(pool, root, n, owner, 40, 0, 100, key, 0, path);
}
