//! FullProof combined-proof layout and public-input decoding.

use outbe_protocol::protocol::zkproof::{decode_public_words, ProofMarshalingError};

pub const PUBLIC_INPUT_COUNT: usize = 4;
pub const PROOF_WORDS: usize = 274;
pub const COMBINED_LEN: usize = 4 + (PUBLIC_INPUT_COUNT + PROOF_WORDS) * 32;

/// Public claim carried by `outbe.full_proof@1.1.0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub derived_owner: [u8; 32],
    pub nft_hash: [u8; 32],
    pub binding_hash: [u8; 32],
    pub merkle_root: [u8; 32],
}

pub fn decode_public_inputs(combined_proof: &[u8]) -> Result<PublicInputs, ProofMarshalingError> {
    let words = decode_public_words::<PUBLIC_INPUT_COUNT>(combined_proof, COMBINED_LEN)?;
    Ok(PublicInputs {
        derived_owner: words[0],
        nft_hash: words[1],
        binding_hash: words[2],
        merkle_root: words[3],
    })
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

    fn combined<const N: usize>(words: [[u8; 32]; N], proof_words: usize) -> Vec<u8> {
        let mut proof = Vec::with_capacity(4 + 32 * (N + proof_words));
        proof.extend_from_slice(&(N as u32).to_be_bytes());
        for word in words {
            proof.extend_from_slice(&word);
        }
        proof.resize(proof.len() + proof_words * 32, 0);
        proof
    }

    #[test]
    fn inputs_decode_in_circuit_order() {
        let words = [
            field_word(11),
            field_word(22),
            field_word(33),
            field_word(44),
        ];
        let proof = combined(words, PROOF_WORDS);
        let decoded = decode_public_inputs(&proof).unwrap();
        assert_eq!(decoded.derived_owner, words[0]);
        assert_eq!(decoded.nft_hash, words[1]);
        assert_eq!(decoded.binding_hash, words[2]);
        assert_eq!(decoded.merkle_root, words[3]);
    }

    #[test]
    fn rejects_wrong_count_length_and_field_encoding() {
        let mut wrong_count = combined([[0; 32]; 4], PROOF_WORDS);
        wrong_count[..4].copy_from_slice(&3u32.to_be_bytes());
        assert!(matches!(
            decode_public_inputs(&wrong_count),
            Err(ProofMarshalingError::WrongPublicInputCount { .. })
        ));

        let wrong_length = combined([[0; 32]; 4], PROOF_WORDS - 1);
        assert!(matches!(
            decode_public_inputs(&wrong_length),
            Err(ProofMarshalingError::WrongCombinedProofLength { .. })
        ));

        let mut words = [[0; 32]; 4];
        let modulus = Fr::MODULUS.to_bytes_be();
        words[2][32 - modulus.len()..].copy_from_slice(&modulus);
        let non_canonical = combined(words, PROOF_WORDS);
        assert_eq!(
            decode_public_inputs(&non_canonical),
            Err(ProofMarshalingError::NonCanonicalPublicInput(2))
        );
    }
}
