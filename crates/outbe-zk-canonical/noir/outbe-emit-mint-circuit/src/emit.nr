//! Emit private-note formulas.
//!
//! Emit formulas use caller-selected purpose tags with the shared iterated
//! Poseidon2 hash. The commitment and nullifier preimages are protocol-wide and
//! live in `outbe_circuit_core::merkle_tree`; the note serial, change-key
//! rotation and empty leaf are Emit's own. Merkle inner nodes use `EMIT_DOMAIN`;
//! the empty leaf uses `OUTBE_EMPTY`.

use outbe_circuit_core::hash::hash_multi;
use outbe_circuit_core::merkle_tree;
use outbe_circuit_core::types::EthAddress;

pub use outbe_circuit_core::merkle_tree::{
    commitment as note_commitment, nullifier, OUTBE_COMMITMENT, OUTBE_NULLIFIER,
};

// Big-endian ASCII tree domain and purpose tags.
pub global EMIT_DOMAIN: Field = 0x4f555442455f454d4954; // "OUTBE_EMIT"
pub global OUTBE_NOTE_SN: Field = 0x4f555442455f4e4f54455f534e; // "OUTBE_NOTE_SN"
pub global OUTBE_CHANGE_KEY: Field = 0x4f555442455f4348414e47455f4b4559; // "OUTBE_CHANGE_KEY"
pub global OUTBE_EMPTY: Field = 0x4f555442455f454d505459; // "OUTBE_EMPTY"

pub fn note_sn(note_owner: EthAddress, note_spend_key: Field) -> Field {
    hash_multi(OUTBE_NOTE_SN, [note_owner.to_field(), note_spend_key])
}

pub fn change_key(note_spend_key: Field, note_nullifier: Field) -> Field {
    hash_multi(OUTBE_CHANGE_KEY, [note_spend_key, note_nullifier])
}

/// Resolve an Emit Merkle root from a compact little-endian leaf index.
pub fn merkle_root<let DEPTH: u32>(
    leaf: Field,
    leaf_index: u32,
    path_siblings: [Field; DEPTH],
) -> Field {
    merkle_tree::merkle_root(EMIT_DOMAIN, leaf, leaf_index as Field, path_siblings)
}

#[test]
fn key_rotation_changes_equal_value_notes() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, 100);
    let spent_nullifier = nullifier(commitment, key);
    let next_key = change_key(key, spent_nullifier);
    let next_serial = note_sn(owner, next_key);
    let next_commitment = note_commitment(chain_id, next_serial, 100);
    let next_nullifier = nullifier(next_commitment, next_key);

    assert(serial != next_serial);
    assert(commitment != next_commitment);
    assert(spent_nullifier != next_nullifier);
}

#[test]
fn distinct_commitments_have_distinct_nullifiers() {
    let chain_id = 31337;
    let owner = EthAddress::from_field(0x2222222222222222222222222222222222222222);
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment_a = note_commitment(chain_id, serial, 40);
    let commitment_b = note_commitment(chain_id, serial, 60);

    assert(commitment_a != commitment_b);
    assert(nullifier(commitment_a, key) != nullifier(commitment_b, key));
}
