//! Emit private-note formulas.
//!
//! Emit hashes are domain-separated iterated Poseidon2 hashes. Merkle inner
//! nodes deliberately use the shared plain `hash2::hash_2([left, right])` tree;
//! only the empty leaf remains Emit-domain-separated.

use outbe_circuit_core::hash2;

// Big-endian ASCII protocol domain and purpose tags.
pub global EMIT_DOMAIN: Field = 0x4f555442455f454d4954; // "OUTBE_EMIT"
pub global TAG_NOTE_SN: Field = 0x454d49545f4e4f54455f534e; // "EMIT_NOTE_SN"
pub global TAG_COMMITMENT: Field = 0x454d49545f434f4d4d49544d454e54; // "EMIT_COMMITMENT"
pub global TAG_NULLIFIER: Field = 0x454d49545f4e554c4c4946494552; // "EMIT_NULLIFIER"
pub global TAG_CHANGE_KEY: Field = 0x454d49545f4348414e47455f4b4559; // "EMIT_CHANGE_KEY"
pub global TAG_EMPTY: Field = 0x454d49545f454d505459; // "EMIT_EMPTY"

pub fn p<let N: u32>(tag: Field, values: [Field; N]) -> Field {
    let mut state = hash2::hash_2([EMIT_DOMAIN, tag]);
    state = hash2::hash_2([state, N as Field]);
    for value in values {
        state = hash2::hash_2([state, value]);
    }
    state
}

pub fn address_field(address: [u8; 20]) -> Field {
    let mut result = 0;
    for byte in address {
        result = result * 256 + byte as Field;
    }
    result
}

pub fn note_sn(note_owner: [u8; 20], note_spend_key: Field) -> Field {
    p(TAG_NOTE_SN, [address_field(note_owner), note_spend_key])
}

pub fn note_commitment(chain_id: u64, serial: Field, note_amount: u64) -> Field {
    p(
        TAG_COMMITMENT,
        [chain_id as Field, serial, note_amount as Field],
    )
}

pub fn nullifier(chain_id: u64, serial: Field, note_spend_key: Field) -> Field {
    p(TAG_NULLIFIER, [chain_id as Field, serial, note_spend_key])
}

pub fn change_key(note_spend_key: Field, note_nullifier: Field) -> Field {
    p(TAG_CHANGE_KEY, [note_spend_key, note_nullifier])
}

pub fn empty_leaf(chain_id: u64) -> Field {
    p(TAG_EMPTY, [chain_id as Field])
}

/// Compute a Merkle root from little-endian path bits.
pub fn merkle_root<let DEPTH: u32>(
    leaf: Field,
    path_siblings: [Field; DEPTH],
    path_bits: [bool; DEPTH],
) -> Field {
    let mut current = leaf;
    for i in 0..DEPTH {
        let sibling = path_siblings[i];
        let (left, right) = if path_bits[i] {
            (sibling, current)
        } else {
            (current, sibling)
        };
        current = hash2::hash_2([left, right]);
    }
    current
}

#[test]
fn address_is_big_endian() {
    assert_eq(address_field([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 1);
}

#[test]
fn key_rotation_changes_equal_value_notes() {
    let chain_id = 31337;
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let spent_nullifier = nullifier(chain_id, serial, key);
    let next_key = change_key(key, spent_nullifier);
    let next_serial = note_sn(owner, next_key);
    let next_commitment = note_commitment(chain_id, next_serial, 100);
    let next_nullifier = nullifier(chain_id, next_serial, next_key);

    assert(serial != next_serial);
    assert(commitment != next_commitment);
    assert(spent_nullifier != next_nullifier);
}

#[test]
fn one_owner_key_pair_has_one_nullifier() {
    let chain_id = 31337;
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment_a = note_commitment(chain_id, serial, 40);
    let commitment_b = note_commitment(chain_id, serial, 60);

    assert(commitment_a != commitment_b);
    assert_eq(nullifier(chain_id, serial, key), nullifier(chain_id, serial, key));
}
