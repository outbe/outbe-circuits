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
pub fn domain() -> Field {
    hash::ascii_field("OUTBE_PLEDGE")
}
fn tagged(purpose: &str, values: &[Field]) -> Result<Field, Error> {
    Pool::hash_multi(Pool::tag(domain(), hash::ascii_field(purpose))?, values)
}
#[cfg(feature = "alloy")]
pub fn owner_serial(owner: Address, secret: Field) -> Result<Field, Error> {
    tagged("owner-serial", &[owner.to_field()?, secret])
}
#[cfg(feature = "alloy")]
pub fn note_commitment(
    chain_id: u64,
    serial: Field,
    amount: U256,
    receipt: Field,
) -> Result<Field, Error> {
    let [lo, mid, hi] = codec::fields_from_u256(&amount)?;
    tagged(
        "pledge-note",
        &[Field::from(chain_id), serial, lo, mid, hi, receipt],
    )
}
pub fn note_nullifier(commitment: Field, secret: Field) -> Result<Field, Error> {
    tagged("pledge-nullifier", &[commitment, secret])
}
pub fn change_key(secret: Field, nullifier: Field) -> Result<Field, Error> {
    tagged("change-key", &[secret, nullifier])
}
pub fn return_key(secret: Field, nullifier: Field, context: Field) -> Result<Field, Error> {
    tagged("return-key", &[secret, nullifier, context])
}
#[cfg(feature = "alloy")]
pub fn receipt_context(position: U256, released_total: U256) -> Result<Field, Error> {
    let p = codec::fields_from_u256(&position)?;
    let a = codec::fields_from_u256(&released_total)?;
    tagged("return-receipt", &[p[0], p[1], p[2], a[0], a[1], a[2]])
}
pub fn empty_leaf(chain_id: u64) -> Result<Field, Error> {
    tagged("empty", &[Field::from(chain_id)])
}
pub fn merkle_node(left: Field, right: Field) -> Result<Field, Error> {
    Tree::node_hash(domain(), left, right)
}
pub fn empty_subtrees(chain_id: u64, depth: usize) -> Result<Vec<Field>, Error> {
    Tree::empty_roots(domain(), empty_leaf(chain_id)?, depth)
}
