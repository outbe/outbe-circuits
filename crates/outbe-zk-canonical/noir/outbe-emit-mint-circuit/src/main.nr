// Emit private-note mint circuit.
//
// Proves knowledge of `(note_amount, note_spend_key, path_bits, auth_path)` for
// a note bound to the public `(chain_id, note_owner)` without revealing the note
// amount or spend key.
//
// The circuit checks that:
//   1. `0 < mint_units <= note_amount`, and the spend key and nullifier are
//      nonzero.
//   2. `note_owner` and `note_spend_key` derive the note serial.
//   3. `(chain_id, serial, note_amount)` derives a nonzero commitment included
//      under the public `root` via the depth-20 `path_bits` and `auth_path`.
//   4. `(chain_id, serial, note_spend_key)` derives the public `nullifier`.
//   5. A partial mint publishes exactly the commitment for the remaining value,
//      using a spend key rotated by the current nullifier; a full mint publishes
//      the zero change sentinel.
//
// The verifier/runtime remains responsible for binding `chain_id`, accepting
// `root`, rejecting an already-spent nullifier, recording any change commitment,
// and authorizing/routing the payout. The payout recipient and ledger state
// transition are not circuit inputs.

mod emit;

use emit::{change_key, empty_leaf, merkle_root, note_commitment, note_sn, nullifier};
use outbe_circuit_core::hash2;

global MERKLE_DEPTH: u32 = 20;

fn main(
    chain_id: pub u64,
    root: pub Field,
    nullifier: pub Field,
    note_owner: pub [u8; 20],
    mint_units: pub u64,
    change_commitment: pub Field,
    note_amount: u64,
    note_spend_key: Field,
    path_bits: [bool; MERKLE_DEPTH],
    auth_path: [Field; MERKLE_DEPTH],
) {
    assert(mint_units > 0);
    assert(mint_units <= note_amount);
    assert(nullifier != 0);
    assert(note_spend_key != 0);

    let serial = note_sn(note_owner, note_spend_key);
    let commitment = note_commitment(chain_id, serial, note_amount);
    let computed_root = merkle_root(commitment, auth_path, path_bits);
    let computed_nullifier = emit::nullifier(chain_id, serial, note_spend_key);

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
        let next_commitment = note_commitment(chain_id, next_serial, remaining);
        let next_nullifier = emit::nullifier(chain_id, next_serial, next_key);
        assert(next_key != 0);
        assert(next_serial != 0);
        assert(next_commitment != 0);
        assert_eq(change_commitment, next_commitment);
        assert(next_nullifier != 0);
    }
}

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
