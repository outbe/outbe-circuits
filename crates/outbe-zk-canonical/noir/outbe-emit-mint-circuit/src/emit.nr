//! Emit private-note formulas.
//!
//! Emit formulas use caller-selected purpose tags with the shared iterated
//! Poseidon2 hash. Merkle inner nodes use `EMIT_DOMAIN`; the empty leaf uses
//! `TAG_EMPTY`.

use outbe_circuit_core::hash::hash_multi;
use outbe_circuit_core::inclusion::compute_merkle_root;
use outbe_circuit_core::types::EthAddress;

// Big-endian ASCII tree domain and purpose tags.
pub global EMIT_DOMAIN: Field = 0x4f555442455f454d4954; // "OUTBE_EMIT"
pub global TAG_NOTE_SN: Field = 0x454d49545f4e4f54455f534e; // "EMIT_NOTE_SN"
pub global TAG_COMMITMENT: Field = 0x454d49545f434f4d4d49544d454e54; // "EMIT_COMMITMENT"
pub global TAG_NULLIFIER: Field = 0x454d49545f4e554c4c4946494552; // "EMIT_NULLIFIER"
pub global TAG_CHANGE_KEY: Field = 0x454d49545f4348414e47455f4b4559; // "EMIT_CHANGE_KEY"
pub global TAG_EMPTY: Field = 0x454d49545f454d505459; // "EMIT_EMPTY"

pub fn note_sn(note_owner: EthAddress, note_spend_key: Field) -> Field {
    hash_multi(TAG_NOTE_SN, [note_owner.to_field(), note_spend_key])
}

pub fn note_commitment(chain_id: u64, serial: Field, note_amount: u64) -> Field {
    hash_multi(
        TAG_COMMITMENT,
        [chain_id as Field, serial, note_amount as Field],
    )
}

pub fn nullifier(chain_id: u64, serial: Field, note_spend_key: Field) -> Field {
    hash_multi(TAG_NULLIFIER, [chain_id as Field, serial, note_spend_key])
}

pub fn change_key(note_spend_key: Field, note_nullifier: Field) -> Field {
    hash_multi(TAG_CHANGE_KEY, [note_spend_key, note_nullifier])
}

/// Resolve an Emit Merkle root from a compact little-endian leaf index.
pub fn merkle_root<let DEPTH: u32>(
    leaf: Field,
    leaf_index: u32,
    path_siblings: [Field; DEPTH],
) -> Field {
    let max_leaf_index = ((1 << DEPTH) - 1) as Field;
    let path_indices: [bool; DEPTH] = (max_leaf_index - leaf_index as Field).to_le_bits();
    compute_merkle_root(EMIT_DOMAIN, leaf, path_siblings, path_indices)
}

#[test]
fn key_rotation_changes_equal_value_notes() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
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
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment_a = note_commitment(chain_id, serial, 40);
    let commitment_b = note_commitment(chain_id, serial, 60);

    assert(commitment_a != commitment_b);
    assert_eq(nullifier(chain_id, serial, key), nullifier(chain_id, serial, key));
}
