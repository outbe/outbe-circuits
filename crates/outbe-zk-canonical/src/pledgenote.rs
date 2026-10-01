//! Owner-bound Gratis notes. Both circuit profiles share this tree and nullifier domain.
use outbe_protocol::{error::Error, Fr};
use outbe_protocol::{primitive::hash, protocol::shielded_pool::ShieldedPool as Pool};
#[cfg(feature = "alloy")]
use {
    alloy_primitives::{Address, U256},
    outbe_protocol::{codec, FieldElement},
};

pub type Field = Fr;
pub type Tree = outbe_protocol::protocol::imt::Imt;
// Keep the original note and tree hash domain.
pub fn domain() -> Field {
    hash::ascii_field("OUTBE_PLEDGE")
}
fn tagged(purpose: Field, values: &[Field]) -> Result<Field, Error> {
    Pool::hash_multi(Pool::tag(domain(), purpose)?, values)
}
#[cfg(feature = "alloy")]
pub fn note_sn(owner: Address, note_spend_key: Field) -> Result<Field, Error> {
    tagged(Pool::tag_note_sn(), &[owner.to_field()?, note_spend_key])
}
#[cfg(feature = "alloy")]
pub fn note_commitment(
    chain_id: u64,
    serial: Field,
    note_amount: U256,
    receipt_context: Field,
) -> Result<Field, Error> {
    let [lo, mid, hi] = codec::fields_from_u256(&note_amount)?;
    tagged(
        Pool::tag_commitment(),
        &[Field::from(chain_id), serial, lo, mid, hi, receipt_context],
    )
}
pub fn note_nullifier(commitment: Field, note_spend_key: Field) -> Result<Field, Error> {
    tagged(Pool::tag_nullifier(), &[commitment, note_spend_key])
}
pub fn change_key(note_spend_key: Field, nullifier: Field) -> Result<Field, Error> {
    tagged(Pool::tag_change_key(), &[note_spend_key, nullifier])
}
pub fn return_key(note_spend_key: Field, nullifier: Field, context: Field) -> Result<Field, Error> {
    tagged(
        hash::ascii_field("RETURN_KEY"),
        &[note_spend_key, nullifier, context],
    )
}
#[cfg(feature = "alloy")]
pub fn receipt_context(position: U256, released_total: U256) -> Result<Field, Error> {
    let p = codec::fields_from_u256(&position)?;
    let a = codec::fields_from_u256(&released_total)?;
    tagged(
        hash::ascii_field("RETURN_RECEIPT"),
        &[p[0], p[1], p[2], a[0], a[1], a[2]],
    )
}
pub fn empty_leaf(chain_id: u64) -> Result<Field, Error> {
    tagged(Pool::tag_empty(), &[Field::from(chain_id)])
}
pub fn merkle_node(left: Field, right: Field) -> Result<Field, Error> {
    Tree::node_hash(domain(), left, right)
}
pub fn empty_subtrees(chain_id: u64, depth: usize) -> Result<Vec<Field>, Error> {
    Tree::empty_roots(domain(), empty_leaf(chain_id)?, depth)
}

#[cfg(all(test, feature = "alloy"))]
mod tests {
    use super::*;

    #[test]
    fn return_tags_match_noir() {
        assert_eq!(
            return_key(Field::from(17u64), Field::from(23u64), Field::from(1u64)).unwrap(),
            tagged(
                Field::from(0x52455455524e5f4b4559u128),
                &[Field::from(17u64), Field::from(23u64), Field::from(1u64)],
            )
            .unwrap(),
        );
        assert_eq!(
            receipt_context(U256::from(1), U256::from(40)).unwrap(),
            tagged(
                Field::from(0x52455455524e5f52454345495054u128),
                &[1u64, 0, 0, 40, 0, 0].map(Field::from),
            )
            .unwrap(),
        );
    }
}
