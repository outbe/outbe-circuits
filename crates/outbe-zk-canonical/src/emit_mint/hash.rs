//! Rust mirror of the Emit hash and tree formulas.
//!
//! Mirrors the frozen circuit formulas in
//! `outbe-emit-mint-circuit/src/emit.nr` and `outbe-circuit-core`'s
//! `hash.nr` / `tags.nr` / `merkle_tree.nr`:
//!
//! - BN254 fields use canonical 32-byte big-endian encodings; a word that
//!   would require reduction is invalid input.
//! - `h2(a, b) = Poseidon2([a, b])[0]` and `h3(a, b, c) = Poseidon2([a, b,
//!   c])[0]` — exactly noir's `hash_2` / `hash_3` (the `outbe-poseidon`
//!   sponge with `len = 2` / `len = 3`).
//! - `hash_multi(tag, values)` mirrors noir `hash_multi(tag, values)`: it absorbs
//!   the tag, the tuple arity, then the ordered values.
//! - Every purpose tag is domain-folded — `h2(EMIT_DOMAIN, base)` with the
//!   shared base tags (`NOTE_SN`, `COMMITMENT`, …) — so no Emit hash can
//!   collide with another domain's hash of the same purpose.
//! - Merkle inner nodes are `h3(EMIT_DOMAIN, left, right)` where
//!   `EMIT_DOMAIN` is the big-endian ASCII `OUTBE_EMIT`.

use alloy_primitives::U256;
use outbe_protocol::{
    codec::u256_limbs_be,
    error::Error,
    protocol::{
        imt::Imt,
        shielded_pool::{self, hash_multi},
    },
    OutbeV1,
};

pub use crate::field::{address_field, field_from_be_bytes, field_to_be_bytes, Field};

/// Big-endian ASCII `OUTBE_EMIT`; 9 bytes fit in u128 and BN254.
pub const EMIT_DOMAIN: u128 = 0x4f555442455f454d4954;

/// The circuit's domain as a field element.
pub fn emit_domain() -> Field {
    Field::from(EMIT_DOMAIN)
}

fn tag(base: Field) -> Result<Field, Error> {
    shielded_pool::tag::<OutbeV1>(emit_domain(), base)
}

pub fn tag_note_sn() -> Result<Field, Error> {
    tag(shielded_pool::tag_note_sn::<OutbeV1>())
}

pub fn tag_commitment() -> Result<Field, Error> {
    tag(shielded_pool::tag_commitment::<OutbeV1>())
}

pub fn tag_nullifier() -> Result<Field, Error> {
    tag(shielded_pool::tag_nullifier::<OutbeV1>())
}

pub fn tag_change_key() -> Result<Field, Error> {
    tag(shielded_pool::tag_change_key::<OutbeV1>())
}

pub fn tag_empty() -> Result<Field, Error> {
    tag(shielded_pool::tag_empty::<OutbeV1>())
}

/// `note_sn = P(EMIT_NOTE_SN, [owner, spend_key])`.
pub fn note_sn(note_owner: [u8; 20], note_spend_key: Field) -> Result<Field, Error> {
    hash_multi::<OutbeV1>(tag_note_sn()?, &[address_field(note_owner), note_spend_key])
}

/// `C = P(EMIT_COMMITMENT, [chain_id, note_sn, amount_limb_0,
/// amount_limb_1, amount_limb_2])` — the only commitment form the runtime ever
/// appends. Hashing every canonical radix-2^120 limb keeps the full uint256
/// amount injective across the BN254 field boundary.
pub fn note_commitment(chain_id: u64, note_sn: Field, note_amount: U256) -> Result<Field, Error> {
    let limbs = u256_limbs_be(&note_amount.to_be_bytes::<32>());
    hash_multi::<OutbeV1>(
        tag_commitment()?,
        &[
            Field::from(chain_id),
            note_sn,
            Field::from(limbs[0]),
            Field::from(limbs[1]),
            Field::from(limbs[2]),
        ],
    )
}

/// `nullifier = P(EMIT_NULLIFIER, [note_commitment, spend_key])` — binds the
/// full commitment (chain, serial, and amount), so distinct commitments
/// always yield distinct nullifiers.
pub fn nullifier(note_commitment: Field, note_spend_key: Field) -> Result<Field, Error> {
    hash_multi::<OutbeV1>(tag_nullifier()?, &[note_commitment, note_spend_key])
}

/// `next_key = P(EMIT_CHANGE_KEY, [spend_key, nullifier])` — the
/// circuit-ratcheted successor key of a partial mint.
pub fn change_key(note_spend_key: Field, note_nullifier: Field) -> Result<Field, Error> {
    hash_multi::<OutbeV1>(tag_change_key()?, &[note_spend_key, note_nullifier])
}

/// Chain-specific empty leaf: `P(EMIT_EMPTY, [chain_id])`.
pub fn empty_leaf(chain_id: u64) -> Result<Field, Error> {
    hash_multi::<OutbeV1>(tag_empty()?, &[Field::from(chain_id)])
}

/// Tagged Merkle inner node: `H3(EMIT_DOMAIN, left, right)`.
pub fn merkle_node(left: Field, right: Field) -> Result<Field, Error> {
    Imt::<OutbeV1>::node_hash(emit_domain(), left, right)
}

/// The complete chain-specific empty ladder `zeros[0..=depth]`:
/// `zeros[0] = empty_leaf(chain_id)`,
/// `zeros[i+1] = H3(EMIT_DOMAIN, zeros[i], zeros[i])`.
/// Derived in memory on every request; never persisted.
pub fn empty_subtrees(chain_id: u64, depth: usize) -> Result<Vec<Field>, Error> {
    Imt::<OutbeV1>::empty_roots(emit_domain(), empty_leaf(chain_id)?, depth)
}
