//! Emit mint combined-proof layout and public-input decoding.

use outbe_protocol::protocol::zkproof::{
    decode_public_words, read_u128_be_padded, read_u64_be_padded,
    ProofMarshalingError as WireMarshalingError,
};

pub const PUBLIC_INPUT_COUNT: usize = 8;
pub const PROOF_WORDS: usize = 250;
pub const COMBINED_LEN: usize = 4 + (PUBLIC_INPUT_COUNT + PROOF_WORDS) * 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MarshalingError {
    #[error(transparent)]
    Wire(#[from] WireMarshalingError),
    #[error("zk_verify: emit chain ID word is not a right-aligned uint64")]
    InvalidChainId,
    #[error("zk_verify: emit owner word exceeds the 160-bit address bound")]
    InvalidOwner,
    #[error("zk_verify: emit mint limb {0} is outside its canonical range")]
    InvalidMintLimb(usize),
}

/// Public claim carried by `outbe.emit.mint@1.5.0` in circuit order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub chain_id: u64,
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub note_owner: [u8; 20],
    /// Three little-endian noir-bignum limbs with radix `2^120`.
    pub mint_units: [u128; 3],
    pub change_commitment: [u8; 32],
}

pub fn decode_public_inputs(combined_proof: &[u8]) -> Result<PublicInputs, MarshalingError> {
    let words = decode_public_words::<PUBLIC_INPUT_COUNT>(combined_proof, COMBINED_LEN)?;

    let chain_id = read_u64_be_padded(&words[0]).ok_or(MarshalingError::InvalidChainId)?;
    if words[3][..12].iter().any(|byte| *byte != 0) {
        return Err(MarshalingError::InvalidOwner);
    }
    let mut note_owner = [0u8; 20];
    note_owner.copy_from_slice(&words[3][12..]);

    let mut mint_units = [0u128; 3];
    for (index, (limb, word)) in mint_units.iter_mut().zip(&words[4..7]).enumerate() {
        *limb = read_u128_be_padded(word).ok_or(MarshalingError::InvalidMintLimb(index))?;
    }
    for (index, limb) in mint_units.iter().copied().enumerate() {
        let limit = if index < 2 { 1u128 << 120 } else { 1u128 << 16 };
        if limb >= limit {
            return Err(MarshalingError::InvalidMintLimb(index));
        }
    }

    Ok(PublicInputs {
        chain_id,
        root: words[1],
        nullifier: words[2],
        note_owner,
        mint_units,
        change_commitment: words[7],
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
        let mut owner = [0u8; 32];
        owner[12..].fill(0x22);
        [
            u64_word(31_337),
            field_word(102),
            field_word(103),
            owner,
            u128_word(40),
            u128_word(1u128 << 80),
            u128_word((1u128 << 16) - 1),
            field_word(104),
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
        assert_eq!(decoded.note_owner, [0x22; 20]);
        assert_eq!(decoded.mint_units, [40, 1u128 << 80, (1u128 << 16) - 1]);
        assert_eq!(decoded.change_commitment, words[7]);
        assert_eq!(proof.len(), COMBINED_LEN);
    }

    #[test]
    fn rejects_wrong_count_and_length() {
        let mut wrong_count = combined(valid_words(), PROOF_WORDS);
        wrong_count[..4].copy_from_slice(&7u32.to_be_bytes());
        assert!(matches!(
            decode_public_inputs(&wrong_count),
            Err(MarshalingError::Wire(
                WireMarshalingError::WrongPublicInputCount { .. }
            ))
        ));

        let wrong_length = combined(valid_words(), PROOF_WORDS + 1);
        assert!(matches!(
            decode_public_inputs(&wrong_length),
            Err(MarshalingError::Wire(
                WireMarshalingError::WrongCombinedProofLength { .. }
            ))
        ));
    }

    #[test]
    fn rejects_invalid_chain_owner_and_limbs() {
        let mut invalid_chain = valid_words();
        invalid_chain[0][23] = 1;
        assert_eq!(
            decode_public_inputs(&combined(invalid_chain, PROOF_WORDS)),
            Err(MarshalingError::InvalidChainId)
        );

        let mut invalid_owner = valid_words();
        invalid_owner[3][11] = 1;
        assert_eq!(
            decode_public_inputs(&combined(invalid_owner, PROOF_WORDS)),
            Err(MarshalingError::InvalidOwner)
        );

        for (index, value) in [(0, 1u128 << 120), (1, 1u128 << 120), (2, 1u128 << 16)] {
            let mut invalid_limb = valid_words();
            invalid_limb[4 + index] = u128_word(value);
            assert_eq!(
                decode_public_inputs(&combined(invalid_limb, PROOF_WORDS)),
                Err(MarshalingError::InvalidMintLimb(index))
            );
        }
    }

    #[test]
    fn accepts_maximum_canonical_u256_limbs() {
        let mut words = valid_words();
        words[4] = u128_word((1u128 << 120) - 1);
        words[5] = u128_word((1u128 << 120) - 1);
        words[6] = u128_word((1u128 << 16) - 1);
        assert_eq!(
            decode_public_inputs(&combined(words, PROOF_WORDS))
                .unwrap()
                .mint_units,
            [(1u128 << 120) - 1, (1u128 << 120) - 1, (1u128 << 16) - 1,]
        );
    }

    #[test]
    fn errors_keep_chain_visible_text() {
        let cases = [
            (
                MarshalingError::InvalidChainId,
                "zk_verify: emit chain ID word is not a right-aligned uint64",
            ),
            (
                MarshalingError::InvalidOwner,
                "zk_verify: emit owner word exceeds the 160-bit address bound",
            ),
            (
                MarshalingError::InvalidMintLimb(1),
                "zk_verify: emit mint limb 1 is outside its canonical range",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }
}
