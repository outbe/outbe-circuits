//! Shared purpose tags and hashing for shielded pools.
//!
//! Domains and concrete note preimages belong to the canonical circuits.

use crate::{error::Error, primitive::hash::FieldHasher, Suite};

// Big-endian ASCII purpose tags matching outbe-circuit-core/src/tags.nr.
const TAG_NOTE_SN: &str = "NOTE_SN";
const TAG_COMMITMENT: &str = "COMMITMENT";
const TAG_NULLIFIER: &str = "NULLIFIER";
const TAG_CHANGE_KEY: &str = "CHANGE_KEY";
const TAG_EMPTY: &str = "EMPTY";

/// Fold a base purpose tag with its owning domain.
pub fn tag<S: Suite>(domain: S::Field, base: S::Field) -> Result<S::Field, Error> {
    S::Hash::hash(&[domain, base])
}

pub fn tag_note_sn<S: Suite>() -> S::Field {
    S::ascii_field(TAG_NOTE_SN)
}

pub fn tag_commitment<S: Suite>() -> S::Field {
    S::ascii_field(TAG_COMMITMENT)
}

pub fn tag_nullifier<S: Suite>() -> S::Field {
    S::ascii_field(TAG_NULLIFIER)
}

pub fn tag_change_key<S: Suite>() -> S::Field {
    S::ascii_field(TAG_CHANGE_KEY)
}

pub fn tag_empty<S: Suite>() -> S::Field {
    S::ascii_field(TAG_EMPTY)
}

/// Noir's hash_multi: absorb the folded tag, tuple length, then each value.
/// Unlike entity hashing, this includes the length even for an empty tuple.
pub fn hash_multi<S: Suite>(tag: S::Field, values: &[S::Field]) -> Result<S::Field, Error> {
    // Slice lengths fit u64 on the supported 32- and 64-bit targets.
    let seed = S::Hash::hash(&[tag, S::Field::from(values.len() as u64)])?;
    S::Hash::iterate(seed, values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OutbeV1;

    #[test]
    fn ascii_tags_match_noir_values() {
        for (actual, expected) in [
            (tag_note_sn::<OutbeV1>(), 0x4e4f54455f534e_u128),
            (tag_commitment::<OutbeV1>(), 0x434f4d4d49544d454e54),
            (tag_nullifier::<OutbeV1>(), 0x4e554c4c4946494552),
            (tag_change_key::<OutbeV1>(), 0x4348414e47455f4b4559),
            (tag_empty::<OutbeV1>(), 0x454d505459),
        ] {
            assert_eq!(actual, <OutbeV1 as Suite>::Field::from(expected));
        }
    }
}
