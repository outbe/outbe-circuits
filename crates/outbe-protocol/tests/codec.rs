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
}
