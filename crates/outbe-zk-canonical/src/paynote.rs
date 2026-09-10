//! Paynote combined-proof layout and public-input decoding.

pub mod hash;

#[cfg(feature = "alloy")]
use alloy_primitives::{Address, B256, U256};
#[cfg(feature = "alloy")]
use ark_ff::{BigInteger, PrimeField};
use outbe_protocol::protocol::shielded_pool::ShieldedPool;
#[cfg(feature = "alloy")]
use outbe_protocol::{
    protocol::zkproof::{decode_public_words, ProofMarshalingError},
    Codec, FieldElement,
};
use outbe_protocol::{OutbeV1, Suite};

/// Cryptographic suite used by Paynote.
pub type PayNoteSuite = OutbeV1;
pub type Field = <PayNoteSuite as Suite>::Field;

pub type Pool = ShieldedPool<OutbeV1>;

/// In-memory commitment tree for Paynote clients.
pub type Tree = outbe_protocol::protocol::imt::Imt<PayNoteSuite>;

pub const PUBLIC_INPUT_COUNT: usize = 9;
pub const PROOF_WORDS: usize = 250;
pub const COMBINED_LEN: usize = 4 + (PUBLIC_INPUT_COUNT + PROOF_WORDS) * 32;

/// Public claim carried by `outbe.paynote@1.2.0` in circuit order.
#[cfg(feature = "alloy")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub chain_id: u64,
    pub root: B256,
    pub nullifier: B256,
    pub asset: Address,
    pub owner: Address,
    pub spend_amount: U256,
    pub change_commitment: B256,
}

/// Decode public inputs using Alloy address, hash, and amount types.
#[cfg(feature = "alloy")]
pub fn decode_public_inputs(combined_proof: &[u8]) -> Result<PublicInputs, ProofMarshalingError> {
    let words = decode_public_words::<PUBLIC_INPUT_COUNT>(combined_proof, COMBINED_LEN)?;

    // decode_public_words has already checked every word for canonicality.
    let fields = words.map(|word| OutbeV1::field_from_be32(&word));
    let chain_id = u64::from_field(&fields[0])
        .map_err(|_| ProofMarshalingError::NonCanonicalPublicInput(0))?;
    let asset = Address::from_field(&fields[3])
        .map_err(|_| ProofMarshalingError::NonCanonicalPublicInput(3))?;
    let owner = Address::from_field(&fields[4])
        .map_err(|_| ProofMarshalingError::NonCanonicalPublicInput(4))?;
    let spend_amount = OutbeV1::fields_to_u256(&fields[5..8]).map_err(|_| {
        // Preserve the offending limb index in the wire error.
        let index = fields[5..8]
            .iter()
            .zip([120, 120, 16])
            .position(|(limb, bits)| limb.into_bigint().num_bits() > bits)
            .expect("invalid U256 limb");
        ProofMarshalingError::NonCanonicalPublicInput(5 + index)
    })?;

    Ok(PublicInputs {
        chain_id,
        root: words[1].into(),
        nullifier: words[2].into(),
        asset,
        owner,
        spend_amount,
        change_commitment: words[8].into(),
    })
}

#[cfg(all(test, feature = "alloy"))]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};

    fn field_word(value: u64) -> [u8; 32] {
        let bytes = Fr::from(value).into_bigint().to_bytes_be();
        let mut word = [0u8; 32];
        word[32 - bytes.len()..].copy_from_slice(&bytes);
        word
    }

    fn u64_word(value: u64) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&value.to_be_bytes());
        word
    }

    fn u128_word(value: u128) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[16..].copy_from_slice(&value.to_be_bytes());
        word
    }

    fn combined<const N: usize>(words: [[u8; 32]; N], proof_words: usize) -> Vec<u8> {
        let mut proof = Vec::with_capacity(4 + 32 * (N + proof_words));
        proof.extend_from_slice(&(N as u32).to_be_bytes());
        for word in words {
            proof.extend_from_slice(&word);
        }
        proof.resize(proof.len() + proof_words * 32, 0);
        proof
    }

    fn valid_words() -> [[u8; 32]; PUBLIC_INPUT_COUNT] {
        let mut asset = [0u8; 32];
        asset[12..].fill(0x11);
        let mut owner = [0u8; 32];
        owner[12..].fill(0x22);
        [
            u64_word(31_337),
            field_word(202),
            field_word(203),
            asset,
            owner,
            u128_word((1u128 << 120) - 1),
            u128_word((1u128 << 120) - 1),
            u128_word((1u128 << 16) - 1),
            field_word(204),
        ]
    }

    #[test]
    fn inputs_decode_current_u256_layout() {
        let words = valid_words();
        let proof = combined(words, PROOF_WORDS);
        let decoded = decode_public_inputs(&proof).unwrap();
        assert_eq!(decoded.chain_id, 31_337);
        assert_eq!(decoded.root, words[1]);
        assert_eq!(decoded.nullifier, words[2]);
        assert_eq!(decoded.asset, Address::from([0x11; 20]));
        assert_eq!(decoded.owner, Address::from([0x22; 20]));
        assert_eq!(decoded.spend_amount, U256::MAX);
        assert_eq!(decoded.change_commitment, words[8]);
        assert_eq!(proof.len(), COMBINED_LEN);
    }

    #[test]
    fn rejects_short_wrong_count_and_wrong_length() {
        assert_eq!(
            decode_public_inputs(&[0u8; 3]),
            Err(ProofMarshalingError::CombinedProofTooShort(3))
        );

        let mut wrong_count = combined(valid_words(), PROOF_WORDS);
        wrong_count[..4].copy_from_slice(&8u32.to_be_bytes());
        assert_eq!(
            decode_public_inputs(&wrong_count),
            Err(ProofMarshalingError::WrongPublicInputCount {
                expected: PUBLIC_INPUT_COUNT,
                actual: 8,
            })
        );

        let wrong_length = combined(valid_words(), PROOF_WORDS - 1);
        assert_eq!(
            decode_public_inputs(&wrong_length),
            Err(ProofMarshalingError::WrongCombinedProofLength {
                expected: COMBINED_LEN,
                actual: COMBINED_LEN - 32,
            })
        );
    }

    #[test]
    fn rejects_oversized_addresses_and_limbs_by_word_index() {
        for (word_index, byte_index) in [(0, 23), (3, 11), (4, 11)] {
            let mut invalid_word = valid_words();
            invalid_word[word_index][byte_index] = 1;
            assert_eq!(
                decode_public_inputs(&combined(invalid_word, PROOF_WORDS)),
                Err(ProofMarshalingError::NonCanonicalPublicInput(word_index))
            );
        }

        for (word_index, value) in [(5, 1u128 << 120), (6, 1u128 << 120), (7, 1u128 << 16)] {
            let mut invalid_limb = valid_words();
            invalid_limb[word_index] = u128_word(value);
            assert_eq!(
                decode_public_inputs(&combined(invalid_limb, PROOF_WORDS)),
                Err(ProofMarshalingError::NonCanonicalPublicInput(word_index))
            );
        }

        for word_index in 5..8 {
            let mut invalid_limb = valid_words();
            invalid_limb[word_index][6] = 1; // 2^200, wider than u128.
            assert_eq!(
                decode_public_inputs(&combined(invalid_limb, PROOF_WORDS)),
                Err(ProofMarshalingError::NonCanonicalPublicInput(word_index))
            );
        }
    }
}
