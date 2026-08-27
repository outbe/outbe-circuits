//! Emit private-note formulas.
//!
//! Every Emit preimage is tagged with `tags::tag(EMIT_DOMAIN, TAG_*)` — a
//! shared base tag folded with Emit's own domain — so no Emit hash can collide
//! with another domain's hash of the same purpose. Only the base tags and the
//! Merkle primitives come from `outbe_circuit_core`; the preimages themselves
//! are Emit's. Merkle inner nodes use `EMIT_DOMAIN` directly.

use outbe_circuit_core::hash::hash_multi;
use outbe_circuit_core::merkle_tree;
use outbe_circuit_core::tags::{
    tag, TAG_CHANGE_KEY, TAG_COMMITMENT, TAG_EMPTY, TAG_NOTE_SN, TAG_NULLIFIER,
};
use outbe_circuit_core::types::EthAddress;

/// Big-endian ASCII tree domain: every Emit tag and Merkle node hangs off it.
pub global EMIT_DOMAIN: Field = 0x4f555442455f454d4954; // "OUTBE_EMIT"

/// Emit's instance of a shared base tag.
pub fn emit_tag(base: Field) -> Field {
    tag(EMIT_DOMAIN, base)
}

/// Value commitment for an Emit note: `(chain_id, serial, amount)`.
pub fn note_commitment(chain_id: u64, serial: Field, amount: u128) -> Field {
    hash_multi(
        emit_tag(TAG_COMMITMENT),
        [chain_id as Field, serial, amount as Field],
    )
}

/// Spend nullifier for an Emit note: `(commitment, spend_key)`.
pub fn nullifier(commitment: Field, spend_key: Field) -> Field {
    hash_multi(emit_tag(TAG_NULLIFIER), [commitment, spend_key])
}

pub fn note_sn(note_owner: EthAddress, note_spend_key: Field) -> Field {
    hash_multi(emit_tag(TAG_NOTE_SN), [note_owner.to_field(), note_spend_key])
}

pub fn change_key(note_spend_key: Field, note_nullifier: Field) -> Field {
    hash_multi(emit_tag(TAG_CHANGE_KEY), [note_spend_key, note_nullifier])
}

/// Empty-leaf value for an Emit tree on `chain_id`.
pub fn empty_leaf(chain_id: u64) -> Field {
    hash_multi(emit_tag(TAG_EMPTY), [chain_id as Field])
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
