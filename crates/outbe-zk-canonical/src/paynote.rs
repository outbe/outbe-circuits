//! Paynote combined-proof layout and public-input decoding.

pub mod hash;

use outbe_protocol::protocol::shielded_pool::ShieldedPool;
use outbe_protocol::{OutbeV1, Suite};

#[cfg(feature = "alloy")]
pub use crate::noir::paynote::alloy::{decode_public_inputs, PublicInputs};
pub use crate::noir::paynote::PUBLIC_INPUT_COUNT;

/// Cryptographic suite used by Paynote.
pub type PayNoteSuite = OutbeV1;
pub type Field = <PayNoteSuite as Suite>::Field;

pub type Pool = ShieldedPool<OutbeV1>;

/// In-memory commitment tree for Paynote clients.
pub type Tree = outbe_protocol::protocol::imt::Imt<PayNoteSuite>;

pub const PROOF_WORDS: usize = 250;
pub const COMBINED_LEN: usize = 4 + (PUBLIC_INPUT_COUNT + PROOF_WORDS) * 32;

#[cfg(all(test, feature = "alloy"))]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use outbe_protocol::protocol::zkproof::ProofMarshalingError;

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

        // Distinct limbs catch reversed limb order as well as shifted ABI offsets.
        let mut words = words;
        words[5] = u128_word(1);
        words[6] = u128_word(2);
        words[7] = u128_word(3);
        assert_eq!(
            decode_public_inputs(&combined(words, PROOF_WORDS)).unwrap(),
            PublicInputs {
                spend_amount: U256::from(1) | (U256::from(2) << 120) | (U256::from(3) << 240),
                ..decoded
            }
        );
    }

    #[test]
    fn rejects_short_wrong_count_and_wrong_length() {
        assert_eq!(
            decode_public_inputs(&[0u8; 3]),
            Err(ProofMarshalingError::CombinedProofTooShort(3))
        );

        assert_eq!(
            decode_public_inputs(&(PUBLIC_INPUT_COUNT as u32).to_be_bytes()),
            Err(ProofMarshalingError::TruncatedPublicInputs {
                expected: 4 + PUBLIC_INPUT_COUNT * 32,
                actual: 4,
            })
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
        for word_index in 0..PUBLIC_INPUT_COUNT {
            let mut words = valid_words();
            words[word_index].copy_from_slice(&Fr::MODULUS.to_bytes_be());
            assert_eq!(
                decode_public_inputs(&combined(words, PROOF_WORDS)),
                Err(ProofMarshalingError::NonCanonicalPublicInput(word_index))
            );
        }

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
