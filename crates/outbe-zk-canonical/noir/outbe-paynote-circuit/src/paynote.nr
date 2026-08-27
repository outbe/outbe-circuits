//! Paynote private ERC20 payment-note formulas.
//!
//! Paynote formulas use caller-selected purpose tags with the shared iterated
//! Poseidon2 hash. The nullifier preimage is protocol-wide and re-exported from
//! `outbe_circuit_core::merkle_tree`; the note serial, change-key rotation and
//! empty leaf are Paynote's own. Merkle inner nodes use `PAYNOTE_DOMAIN`; the
//! empty leaf uses `TAG_EMPTY`.
//!
//! `hash_multi` seeds with `hash_2([tag, N])` -- there is no separate domain
//! pre-mix, so cross-circuit separation rests entirely on these tag strings
//! being distinct from every other circuit's. `PAYNOTE_DOMAIN` survives only as
//! the tree tag.
//!
//! The commitment is Paynote's own rather than `merkle_tree::commitment`,
//! because it binds a fourth field: the asset. The asset lives in the
//! **commitment**, not the serial. The pool contract derives a deposit leaf from
//! the asset and amount it actually pulled, so the leaf -- and therefore Merkle
//! membership -- attests both. An asset carried in the serial would be
//! user-supplied and unverifiable at deposit time, letting a depositor fund a
//! note in a cheap token and spend it as an expensive one.

use outbe_circuit_core::hash::hash_multi;
use outbe_circuit_core::merkle_tree;
use outbe_circuit_core::types::EthAddress;

/// Spend nullifier, derived from the **commitment** rather than the serial, so
/// every leaf has exactly one nullifier. That is what makes two leaves sharing
/// a serial harmless: their amounts differ, so their commitments differ, so
/// their nullifiers differ and both stay spendable. It also binds the asset and
/// the amount for free. `chain_id` is deliberately absent -- the commitment
/// already binds it.
pub use outbe_circuit_core::merkle_tree::{nullifier, OUTBE_NULLIFIER};

// Big-endian ASCII tree domain and purpose tags.
pub global PAYNOTE_DOMAIN: Field = 0x4f555442455f5041594e4f5445; // "OUTBE_PAYNOTE"
pub global TAG_NOTE_SN: Field = 0x5041594e4f54455f4e4f54455f534e; // "PAYNOTE_NOTE_SN"
pub global TAG_COMMITMENT: Field = 0x5041594e4f54455f434f4d4d49544d454e54; // "PAYNOTE_COMMITMENT"
pub global TAG_CHANGE_KEY: Field = 0x5041594e4f54455f4348414e47455f4b4559; // "PAYNOTE_CHANGE_KEY"
pub global TAG_EMPTY: Field = 0x5041594e4f54455f454d505459; // "PAYNOTE_EMPTY"

/// Note serial -- a hiding commitment to the spend key. Chain-, asset- and
/// amount-independent, so the pool contract can accept one at deposit time and
/// build the leaf around it.
pub fn note_sn(note_spend_key: Field) -> Field {
    hash_multi(TAG_NOTE_SN, [note_spend_key])
}

/// Note commitment -- the Merkle leaf. Binds the asset and the amount, both of
/// which the pool contract fills in from the transfer it actually performed.
pub fn note_commitment(
    chain_id: u64,
    serial: Field,
    asset: EthAddress,
    note_amount: u128,
) -> Field {
    hash_multi(
        TAG_COMMITMENT,
        [chain_id as Field, serial, asset.to_field(), note_amount as Field],
    )
}

pub fn change_key(note_spend_key: Field, note_nullifier: Field) -> Field {
    hash_multi(TAG_CHANGE_KEY, [note_spend_key, note_nullifier])
}

/// Resolve a Paynote Merkle root from a compact little-endian leaf index.
pub fn merkle_root<let DEPTH: u32>(
    leaf: Field,
    leaf_index: u32,
    path_siblings: [Field; DEPTH],
) -> Field {
    merkle_tree::merkle_root(PAYNOTE_DOMAIN, leaf, leaf_index as Field, path_siblings)
}

#[test]
fn asset_separates_equal_value_notes() {
    let chain_id = 31337;
    let usdc = EthAddress::from_field(0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48);
    let wbtc = EthAddress::from_field(0x2260fac5e5542a773aa44fbcfedf7c193bc2c599);
    let serial = note_sn(17);

    assert(
        note_commitment(chain_id, serial, usdc, 100)
            != note_commitment(chain_id, serial, wbtc, 100),
    );
}

#[test]
fn key_rotation_changes_equal_value_notes() {
    let chain_id = 31337;
    let asset = EthAddress::from_field(0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48);
    let key = 17;
    let serial = note_sn(key);
    let commitment = note_commitment(chain_id, serial, asset, 100);
    let spent_nullifier = nullifier(commitment, key);
    let next_key = change_key(key, spent_nullifier);
    let next_serial = note_sn(next_key);
    let next_commitment = note_commitment(chain_id, next_serial, asset, 100);
    let next_nullifier = nullifier(next_commitment, next_key);

    assert(serial != next_serial);
    assert(commitment != next_commitment);
    assert(spent_nullifier != next_nullifier);
}

/// Binding the nullifier to the commitment -- not the serial -- is what makes a
/// serial collision harmless. Two leaves under one serial carry different
/// amounts, so they hash to different commitments and yield distinct
/// nullifiers; both remain spendable. Bind the serial instead and they would
/// alias onto one nullifier, locking one of the two up forever.
#[test]
fn one_serial_two_amounts_have_distinct_nullifiers() {
    let chain_id = 31337;
    let asset = EthAddress::from_field(0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48);
    let key = 17;
    let serial = note_sn(key);
    let commitment_a = note_commitment(chain_id, serial, asset, 40);
    let commitment_b = note_commitment(chain_id, serial, asset, 60);

    assert(commitment_a != commitment_b);
    assert(nullifier(commitment_a, key) != nullifier(commitment_b, key));
    assert_eq(nullifier(commitment_a, key), nullifier(commitment_a, key));
}
