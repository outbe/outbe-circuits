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

use crate::emit_mint::{Field, Pool, Tree};
#[cfg(feature = "alloy")]
use alloy_primitives::{Address, U256};
use ark_ff::{BigInteger, PrimeField};
use outbe_protocol::{codec::field_from_be_bytes, error::Error, OutbeV1, Suite};
#[cfg(feature = "alloy")]
use outbe_protocol::{Codec, FieldElement};

/// Big-endian ASCII domain; 9 bytes fit in the proving field.
pub const EMIT_DOMAIN: &str = "OUTBE_EMIT";

/// The circuit's domain as a field element.
pub fn emit_domain() -> Field {
    OutbeV1::ascii_field(EMIT_DOMAIN)
}

fn tag(base: Field) -> Result<Field, Error> {
    Pool::tag(emit_domain(), base)
}

pub fn tag_note_sn() -> Result<Field, Error> {
    tag(Pool::tag_note_sn())
}

pub fn tag_commitment() -> Result<Field, Error> {
    tag(Pool::tag_commitment())
}

pub fn tag_nullifier() -> Result<Field, Error> {
    tag(Pool::tag_nullifier())
}

pub fn tag_change_key() -> Result<Field, Error> {
    tag(Pool::tag_change_key())
}

pub fn tag_empty() -> Result<Field, Error> {
    tag(Pool::tag_empty())
}

/// `note_sn = P(EMIT_NOTE_SN, [owner, spend_key])`.
#[cfg(feature = "alloy")]
pub fn note_sn(note_owner: Address, note_spend_key: Field) -> Result<Field, Error> {
    Pool::hash_multi(tag_note_sn()?, &[note_owner.to_field()?, note_spend_key])
}

/// Derive a note serial from a 20-byte owner address.
pub fn note_sn_raw(note_owner: [u8; 20], note_spend_key: Field) -> Result<Field, Error> {
    Pool::hash_multi(
        tag_note_sn()?,
        &[field_from_be_bytes(&note_owner), note_spend_key],
    )
}

/// `C = P(EMIT_COMMITMENT, [chain_id, note_sn, amount_limb_0,
/// amount_limb_1, amount_limb_2])` — the only commitment form the runtime ever
/// appends. Hashing every canonical radix-2^120 limb keeps the full uint256
/// amount injective across the BN254 field boundary.
#[cfg(feature = "alloy")]
pub fn note_commitment(chain_id: u64, note_sn: Field, note_amount: U256) -> Result<Field, Error> {
    let [lo, mid, hi] = OutbeV1::fields_from_u256(&note_amount)?;
    Pool::hash_multi(
        tag_commitment()?,
        &[chain_id.to_field()?, note_sn, lo, mid, hi],
    )
}

/// Commit to a note with three canonical radix-`2^120` amount fields.
/// Rejects limbs outside the `[120, 120, 16]`-bit bounds.
pub fn note_commitment_raw(
    chain_id: u64,
    note_sn: Field,
    note_amount: [Field; 3],
) -> Result<Field, Error> {
    if note_amount
        .iter()
        .zip([120, 120, 16])
        .any(|(limb, bits)| limb.into_bigint().num_bits() > bits)
    {
        return Err(Error::NonCanonical("uint256 limbs"));
    }
    let [lo, mid, hi] = note_amount;
    Pool::hash_multi(
        tag_commitment()?,
        &[Field::from(chain_id), note_sn, lo, mid, hi],
    )
}

/// `nullifier = P(EMIT_NULLIFIER, [note_commitment, spend_key])` — binds the
/// full commitment (chain, serial, and amount), so distinct commitments
/// always yield distinct nullifiers.
pub fn nullifier(note_commitment: Field, note_spend_key: Field) -> Result<Field, Error> {
    Pool::hash_multi(tag_nullifier()?, &[note_commitment, note_spend_key])
}

/// `next_key = P(EMIT_CHANGE_KEY, [spend_key, nullifier])` — the
/// circuit-ratcheted successor key of a partial mint.
pub fn change_key(note_spend_key: Field, note_nullifier: Field) -> Result<Field, Error> {
    Pool::hash_multi(tag_change_key()?, &[note_spend_key, note_nullifier])
}

/// Chain-specific empty leaf: `P(EMIT_EMPTY, [chain_id])`.
pub fn empty_leaf(chain_id: u64) -> Result<Field, Error> {
    Pool::hash_multi(tag_empty()?, &[Field::from(chain_id)])
}

/// Tagged Merkle inner node: `H3(EMIT_DOMAIN, left, right)`.
pub fn merkle_node(left: Field, right: Field) -> Result<Field, Error> {
    Tree::node_hash(emit_domain(), left, right)
}

/// The complete chain-specific empty ladder `zeros[0..=depth]`:
/// `zeros[0] = empty_leaf(chain_id)`,
/// `zeros[i+1] = H3(EMIT_DOMAIN, zeros[i], zeros[i])`.
/// Derived in memory on every request; never persisted.
pub fn empty_subtrees(chain_id: u64, depth: usize) -> Result<Vec<Field>, Error> {
    Tree::empty_roots(emit_domain(), empty_leaf(chain_id)?, depth)
}

#[cfg(all(test, feature = "alloy"))]
mod tests {
    use super::*;

    #[test]
    fn alloy_hashes_match_raw() {
        let amounts = [
            (U256::ZERO, [0, 0, 0]),
            (U256::from(1), [1, 0, 0]),
            (U256::from(1) << 120usize, [0, 1, 0]),
            (U256::from(1) << 240usize, [0, 0, 1]),
            (
                (U256::from(1) << 200usize) + U256::from(7),
                [7, 1u128 << 80, 0],
            ),
            (
                U256::MAX,
                [(1u128 << 120) - 1, (1u128 << 120) - 1, u16::MAX as u128],
            ),
        ];
        for (chain_id, key, address) in [
            (0, Field::from(0u64), [0; 20]),
            (
                31_337,
                Field::from(17u64),
                core::array::from_fn(|i| i as u8),
            ),
            (u64::MAX, -Field::from(1u64), [0xff; 20]),
        ] {
            let serial = note_sn(Address::from(address), key).unwrap();
            assert_eq!(serial, note_sn_raw(address, key).unwrap());
            for (amount, limbs) in amounts {
                assert_eq!(
                    note_commitment(chain_id, serial, amount).unwrap(),
                    note_commitment_raw(chain_id, serial, limbs.map(Field::from)).unwrap(),
                    "chain_id={chain_id}, amount={amount}",
                );
            }
        }
    }
}
