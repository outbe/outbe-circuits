//! Canonical field encoding at the protocol byte boundary.

use outbe_protocol::{codec::field_from_be_bytes_canonical, Codec, OutbeV1, Suite};

type Field = <OutbeV1 as Suite>::Field;

#[test]
fn primitive_from_field_checks_target_range() {
    use outbe_protocol::FieldElement;

    macro_rules! check_integer {
        ($($t:ty),*) => {$(
            for value in [0, 1, <$t>::MAX] {
                let field: Field = value.to_field().unwrap();
                assert_eq!(<$t>::from_field(&field).unwrap(), value);
            }
            let overflow = Field::from(<$t>::MAX) + Field::from(1u64);
            assert!(<$t>::from_field(&overflow).is_err());
            assert!(<$t>::from_field(&-Field::from(1u64)).is_err());
        )*};
    }
    check_integer!(u8, u16, u32, u64, u128);

    for value in [false, true] {
        let field: Field = value.to_field().unwrap();
        assert_eq!(bool::from_field(&field).unwrap(), value);
    }
    for value in [Field::from(2u64), Field::from(256u64), -Field::from(1u64)] {
        assert!(bool::from_field(&value).is_err());
    }
}

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
        let field = OutbeV1::field_from_b256(&word).unwrap();
        assert_eq!(OutbeV1::field_to_b256(&field).unwrap(), word);
        assert_eq!(FieldElement::<Field>::to_field(&word).unwrap(), field);
        assert_eq!(B256::from_field(&field).unwrap(), word);
    }
    for integer in [modulus, modulus + U256::from(1), U256::MAX] {
        assert!(OutbeV1::field_from_b256(&B256::from(integer.to_be_bytes::<32>())).is_err());
    }
}

#[cfg(feature = "alloy")]
#[test]
fn codec_u256_uses_canonical_field_limbs() {
    use alloy_primitives::U256;
    use outbe_protocol::{codec::u256_limbs_be, FieldEncode};

    for value in [
        U256::ZERO,
        U256::from(1),
        U256::from(1) << 120,
        U256::from(1) << 240,
        (U256::from(1) << 200) + U256::from(100),
        U256::MAX,
    ] {
        let fields: [Field; 3] = OutbeV1::fields_from_u256(&value).unwrap();
        let mut encoded: Vec<Field> = Vec::new();
        value.encode(&mut encoded).unwrap();
        assert_eq!(fields.as_slice(), encoded.as_slice());
        assert_eq!(
            fields,
            u256_limbs_be(&value.to_be_bytes::<32>()).map(Field::from)
        );
        assert_eq!(OutbeV1::fields_to_u256(&fields).unwrap(), value);
    }

    for (index, bits) in [(0, 120), (1, 120), (2, 16)] {
        let mut fields = [Field::from(0u64); 3];
        fields[index] = Field::from(1u128 << bits);
        assert!(OutbeV1::fields_to_u256(&fields).is_err());
        fields[index] = -Field::from(1u64);
        assert!(OutbeV1::fields_to_u256(&fields).is_err());
    }
    for len in [0, 1, 2, 4] {
        assert!(OutbeV1::fields_to_u256(&vec![Field::from(0u64); len]).is_err());
    }
}

#[cfg(feature = "alloy")]
#[test]
fn alloy_from_field_checks_target_range() {
    use alloy_primitives::{Address, U16, U32, U64};
    use outbe_protocol::FieldElement;

    for bytes in [[0u8; 20], [0xff; 20], std::array::from_fn(|i| i as u8)] {
        let address = Address::from(bytes);
        let field: Field = address.to_field().unwrap();
        assert_eq!(Address::from_field(&field).unwrap(), address);
    }
    let max: Field = Address::from([0xff; 20]).to_field().unwrap();
    assert!(Address::from_field(&(max + Field::from(1u64))).is_err());

    macro_rules! check_integer {
        ($($t:ty),*) => {$(
            for value in [<$t>::ZERO, <$t>::from(1), <$t>::MAX] {
                let field: Field = value.to_field().unwrap();
                assert_eq!(<$t>::from_field(&field).unwrap(), value);
            }
            let max: Field = <$t>::MAX.to_field().unwrap();
            assert!(<$t>::from_field(&(max + Field::from(1u64))).is_err());
            assert!(<$t>::from_field(&-Field::from(1u64)).is_err());
        )*};
    }
    check_integer!(U16, U32, U64);
}
