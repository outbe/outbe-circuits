//! BN254 field words used by the canonical circuits.

use ark_ff::{BigInteger, PrimeField};
use outbe_protocol::codec::field_from_be_bytes_canonical;

pub type Field = ark_bn254::Fr;

/// A 160-bit address is smaller than the BN254 scalar modulus.
pub fn address_field(address: [u8; 20]) -> Field {
    outbe_protocol::codec::field_from_be_bytes(&address)
}

/// Canonical 32-byte big-endian field word.
pub fn field_to_be_bytes(value: Field) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Reject words that would require reduction modulo the field order.
pub fn field_from_be_bytes(bytes: &[u8; 32]) -> Option<Field> {
    field_from_be_bytes_canonical(bytes, "BN254 field").ok()
}
