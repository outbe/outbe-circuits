//! Base purpose tags, shared by every circuit.
//!
//! A tag names *what* is being hashed (a commitment, a nullifier, ...); a
//! domain names *whose* it is (`EMIT_DOMAIN`, `DEMO_TRIBUTE_DOMAIN`, ...). The
//! value actually fed to `hash_multi` is the two combined:
//!
//! ```noir
//! let tag = tags::tag(EMIT_DOMAIN, tags::TAG_COMMITMENT);
//! let commitment = hash_multi(tag, [...]);
//! ```

use crate::hash::{ascii_field, hash_2};

// Big-endian ASCII purpose tags.
pub global TAG_COMMITMENT: Field = ascii_field("COMMITMENT");
pub global TAG_NULLIFIER: Field = ascii_field("NULLIFIER");
pub global TAG_NOTE_SN: Field = ascii_field("NOTE_SN");
pub global TAG_CHANGE_KEY: Field = ascii_field("CHANGE_KEY");
pub global TAG_EMPTY: Field = ascii_field("EMPTY");

/// Domain-separated tag: `Poseidon2(domain, base_tag)`.
pub fn tag(domain: Field, base: Field) -> Field {
    hash_2([domain, base])
}

#[test]
fn base_tags_are_pairwise_distinct_and_nonzero() {
    let tags = [TAG_COMMITMENT, TAG_NULLIFIER, TAG_NOTE_SN, TAG_CHANGE_KEY, TAG_EMPTY];
    for i in 0..tags.len() {
        assert(tags[i] != 0);
        for j in (i + 1)..tags.len() {
            assert(tags[i] != tags[j]);
        }
    }
}

/// Same base tag under two domains must not collide -- the whole point.
#[test]
fn domains_separate_the_same_base_tag() {
    assert(tag(1, TAG_COMMITMENT) != tag(2, TAG_COMMITMENT));
    assert(tag(1, TAG_COMMITMENT) != tag(1, TAG_NULLIFIER));
}
