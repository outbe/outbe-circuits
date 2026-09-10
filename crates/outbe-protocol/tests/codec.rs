//! Canonical field encoding at the protocol byte boundary.

use outbe_protocol::{codec::field_from_be_bytes_canonical, Codec, OutbeV1, Suite};

type Field = <OutbeV1 as Suite>::Field;

#[test]
fn field_words_remain_canonical() {
    use ark_ff::{BigInteger, PrimeField};
    for value in [Field::from(0u64), Field::from(1u64), -Field::from(1u64)] {
        assert_eq!(
            field_from_be_bytes_canonical::<Field>(&OutbeV1::field_to_be_bytes(&value), "field")
                .unwrap(),
            value
        );
    }
    let modulus: [u8; 32] = Field::MODULUS.to_bytes_be().try_into().unwrap();
    assert!(field_from_be_bytes_canonical::<Field>(&modulus, "field").is_err());
    assert!(field_from_be_bytes_canonical::<Field>(&[0xff; 32], "field").is_err());

    let mut oversized = [0u8; 33];
    oversized[0] = 1;
    assert!(field_from_be_bytes_canonical::<Field>(&oversized, "field").is_err());
    oversized[0] = 0;
    oversized[32] = 1;
    assert_eq!(
        field_from_be_bytes_canonical::<Field>(&oversized, "field").unwrap(),
        Field::from(1u64)
    );
}

#[cfg(feature = "alloy")]
#[test]
fn alloy_field_words_roundtrip_and_reject_noncanonical_values() {
    use alloy_primitives::{B256, U256};
    use ark_ff::{BigInteger, PrimeField};
    use outbe_protocol::FieldElement;

    let modulus = U256::from_be_slice(&Field::MODULUS.to_bytes_be());
    for integer in [
        U256::ZERO,
        U256::from(1),
        (U256::from(1) << 200) + U256::from(0x1234),
        modulus - U256::from(1),
    ] {
        let word = B256::from(integer.to_be_bytes::<32>());
        let field = OutbeV1::field_from_u256(&integer).unwrap();
        assert_eq!(OutbeV1::field_to_u256(&field).unwrap(), integer);
        assert_eq!(OutbeV1::field_from_b256(&word).unwrap(), field);
        assert_eq!(OutbeV1::field_to_b256(&field).unwrap(), word);
        assert_eq!(FieldElement::<Field>::to_field(&word).unwrap(), field);
    }
    for integer in [modulus, modulus + U256::from(1), U256::MAX] {
        assert!(OutbeV1::field_from_u256(&integer).is_err());
        assert!(OutbeV1::field_from_b256(&B256::from(integer.to_be_bytes::<32>())).is_err());
    }
}
