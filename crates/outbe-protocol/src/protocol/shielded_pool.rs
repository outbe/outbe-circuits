//! Shared purpose tags and hashing for shielded pools.
//!
//! Domains and concrete note preimages belong to the canonical circuits.

use crate::{error::Error, primitive::hash::FieldHasher, Suite};

// Big-endian ASCII, matching outbe-circuit-core/src/tags.nr. Each value
// fits in u128 (at most 10 ASCII bytes), without field-modulus reduction.
pub const TAG_NOTE_SN: u128 = 0x4e4f54455f534e;
pub const TAG_COMMITMENT: u128 = 0x434f4d4d49544d454e54;
pub const TAG_NULLIFIER: u128 = 0x4e554c4c4946494552;
pub const TAG_CHANGE_KEY: u128 = 0x4348414e47455f4b4559;
pub const TAG_EMPTY: u128 = 0x454d505459;

/// Fold a base purpose tag with its owning domain.
pub fn tag<S: Suite>(domain: S::Field, base: u128) -> Result<S::Field, Error> {
    S::Hash::hash(&[domain, S::Field::from(base)])
}

/// Noir's hash_multi: absorb the folded tag, tuple length, then each value.
/// Unlike entity hashing, this includes the length even for an empty tuple.
pub fn hash_multi<S: Suite>(tag: S::Field, values: &[S::Field]) -> Result<S::Field, Error> {
    // Slice lengths fit u64 on the supported 32- and 64-bit targets.
    let seed = S::Hash::hash(&[tag, S::Field::from(values.len() as u64)])?;
    S::Hash::iterate(seed, values)
}
