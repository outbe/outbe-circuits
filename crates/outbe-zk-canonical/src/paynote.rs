//! Paynote combined-proof layout and public-input decoding.

use alloy_primitives::{Address, U256};
use outbe_protocol::codec::u256_from_limbs_be;

use outbe_protocol::protocol::zkproof::{
    decode_public_words, read_u128_be_padded, read_u64_be_padded, ProofMarshalingError,
};

pub const PUBLIC_INPUT_COUNT: usize = 9;
pub const PROOF_WORDS: usize = 250;
pub const COMBINED_LEN: usize = 4 + (PUBLIC_INPUT_COUNT + PROOF_WORDS) * 32;

/// Public claim carried by `outbe.paynote@1.1.0` in circuit order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub chain_id: u64,
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub asset: Address,
    pub spender: Address,
    pub spend_amount: U256,
    pub change_commitment: [u8; 32],
}

pub fn decode_public_inputs(combined_proof: &[u8]) -> Result<PublicInputs, ProofMarshalingError> {
    let words = decode_public_words::<PUBLIC_INPUT_COUNT>(combined_proof, COMBINED_LEN)?;

    let chain_id =
        read_u64_be_padded(&words[0]).ok_or(ProofMarshalingError::NonCanonicalPublicInput(0))?;
    let asset = read_address_be_padded(&words[3])
        .ok_or(ProofMarshalingError::NonCanonicalPublicInput(3))?;
    let spender = read_address_be_padded(&words[4])
        .ok_or(ProofMarshalingError::NonCanonicalPublicInput(4))?;
    let mut limbs = [0u128; 3];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let word_index = 5 + index;
        *limb = read_u128_be_padded(&words[word_index])
            .ok_or(ProofMarshalingError::NonCanonicalPublicInput(word_index))?;
        let limit = if index < 2 { 1u128 << 120 } else { 1u128 << 16 };
        if *limb >= limit {
            return Err(ProofMarshalingError::NonCanonicalPublicInput(word_index));
        }
    }
    let spend_amount =
        U256::from_be_bytes(u256_from_limbs_be(limbs).expect("validated canonical U256 limbs"));

    Ok(PublicInputs {
        chain_id,
        root: words[1],
        nullifier: words[2],
        asset,
        spender,
        spend_amount,
        change_commitment: words[8],
    })
}

fn read_address_be_padded(slot: &[u8]) -> Option<Address> {
    if slot.len() != 32 || slot[..12].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(&slot[12..]);
    Some(Address::from(address))
}

#[cfg(test)]
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
        let mut spender = [0u8; 32];
        spender[12..].fill(0x22);
        [
            u64_word(31_337),
            field_word(202),
            field_word(203),
            asset,
            spender,
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
        assert_eq!(decoded.spender, Address::from([0x22; 20]));
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
        let mut invalid_address = valid_words();
        invalid_address[3][11] = 1;
        assert_eq!(
            decode_public_inputs(&combined(invalid_address, PROOF_WORDS)),
            Err(ProofMarshalingError::NonCanonicalPublicInput(3))
        );

        for (word_index, value) in [(5, 1u128 << 120), (6, 1u128 << 120), (7, 1u128 << 16)] {
            let mut invalid_limb = valid_words();
            invalid_limb[word_index] = u128_word(value);
            assert_eq!(
                decode_public_inputs(&combined(invalid_limb, PROOF_WORDS)),
                Err(ProofMarshalingError::NonCanonicalPublicInput(word_index))
            );
        }
    }
}
