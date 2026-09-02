//! `#[outbe(limbed)]` — single (default) vs. limbed scalar width.
//!
//! A scalar body field folds to **exactly one** field element by default
//! (`FieldElement::to_field`). `#[outbe(limbed)]` instead routes it through
//! [`outbe_protocol::FieldEncode`], which yields the multiple elements its type
//! needs (e.g. a `uint256` → `[120, 120, 16]`-bit limbs). The flag carries *intent* only — the
//! limb count is a property of the type, not the annotation.
//!
//! Drift-proofing: a wide type used **without** `limbed` is bound
//! `T: FieldElement`, which it does not implement, so it fails to build. The
//! commented `WithoutLimbed` struct below is that compile-fail (no `trybuild`
//! dep, so it's documented rather than asserted).

use ark_ff::PrimeField;
use outbe_protocol::error::Error;
use outbe_protocol::protocol::entity::Entity as EntityTrait;
use outbe_protocol::{FieldElement, FieldEncode, OutbeV1, Suite};
use outbe_protocol_derive::Entity;

type F = <OutbeV1 as Suite>::Field;

/// A two-element scalar (a stand-in for a `uint256`): its `FieldEncode` emits
/// two elements, and it is deliberately **not** a `FieldElement`, so it can
/// only be folded via `#[outbe(limbed)]`.
#[derive(Clone)]
struct Pair(u64, u64);

impl<Fp: PrimeField> FieldEncode<Fp> for Pair {
    fn encode(&self, out: &mut Vec<Fp>) -> Result<(), Error> {
        out.push(Fp::from(self.0));
        out.push(Fp::from(self.1));
        Ok(())
    }
}

#[derive(Entity)]
struct WithLimbed {
    #[outbe(id_seed)]
    id: u64,
    #[outbe(body, pos = 0)]
    single: u64,
    #[outbe(body, pos = 1, limbed)]
    wide: Pair,
}

// Compile-fail (intentional): without `limbed`, `wide` is bound
// `Pair: FieldElement`, which `Pair` does not implement.
//
// #[derive(Entity)]
// struct WithoutLimbed {
//     #[outbe(id_seed)] id: u64,
//     #[outbe(body)]    wide: Pair, // ERROR: the trait bound `Pair: FieldElement<_>` is not satisfied
// }

/// A default scalar contributes exactly one element (its `to_field`); a
/// `limbed` scalar contributes the elements of its `FieldEncode` — here two,
/// byte-identical to calling `FieldEncode` directly.
#[test]
fn limbed_uses_field_encode_width_default_is_single() {
    let e = WithLimbed {
        id: 1,
        single: 7,
        wide: Pair(11, 22),
    };
    let mut body = Vec::new();
    EntityTrait::<OutbeV1>::encode_body(&e, &mut body).unwrap();

    // single → 1 element; limbed `Pair` → 2 elements ⇒ 3 total.
    assert_eq!(body.len(), 3, "expected 1 (single) + 2 (limbed) elements");

    // The default scalar is exactly its `to_field` (so single fields stay
    // hash-neutral vs. the old `FieldEncode`-of-a-single path).
    assert_eq!(body[0], FieldElement::<F>::to_field(&7u64).unwrap());

    // The limbed scalar is exactly its `FieldEncode` output.
    let mut wide = Vec::new();
    FieldEncode::<F>::encode(&Pair(11, 22), &mut wide).unwrap();
    assert_eq!(&body[1..3], &wide[..], "limbed field != its FieldEncode");
}

#[cfg(feature = "alloy")]
#[test]
fn alloy_u256_uses_the_noir_bignum_limb_layout() {
    use alloy_primitives::U256;
    use outbe_protocol::codec::u256_limbs_be;

    let value: U256 = (U256::from(1) << 200) + U256::from(100);
    let mut encoded = Vec::new();
    FieldEncode::<F>::encode(&value, &mut encoded).unwrap();

    let limbs = u256_limbs_be(&value.to_be_bytes::<32>());
    assert_eq!(limbs, [100, 1u128 << 80, 0]);
    assert_eq!(encoded, limbs.map(F::from));
}
