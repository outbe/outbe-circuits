//! Emit mint combined-proof layout and public-input decoding.

pub mod hash;

use alloy_primitives::{Address, B256, U256};
use ark_ff::{BigInteger, PrimeField};
use outbe_protocol::protocol::shielded_pool::ShieldedPool;
use outbe_protocol::{
    protocol::zkproof::{decode_public_words, ProofMarshalingError as WireMarshalingError},
    Codec, FieldElement, OutbeV1, Suite,
};

/// Cryptographic suite used by Emit.
pub type EmitSuite = OutbeV1;
pub type Field = <EmitSuite as Suite>::Field;

pub type Pool = ShieldedPool<OutbeV1>;

/// In-memory commitment tree for Emit clients.
pub type Tree = outbe_protocol::protocol::imt::Imt<EmitSuite>;

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
    pub root: B256,
    pub nullifier: B256,
    pub note_owner: Address,
    /// Full-width amount decoded from three canonical radix-`2^120` limbs.
    pub mint_units: U256,
    pub change_commitment: B256,
}

pub fn decode_public_inputs(combined_proof: &[u8]) -> Result<PublicInputs, MarshalingError> {
    let words = decode_public_words::<PUBLIC_INPUT_COUNT>(combined_proof, COMBINED_LEN)?;

    // decode_public_words has already checked every word for canonicality.
    let fields = words.map(|word| OutbeV1::field_from_be32(&word));
    let chain_id = u64::from_field(&fields[0]).map_err(|_| MarshalingError::InvalidChainId)?;
    let note_owner = Address::from_field(&fields[3]).map_err(|_| MarshalingError::InvalidOwner)?;
    let mint_units = OutbeV1::fields_to_u256(&fields[4..7]).map_err(|_| {
        // Preserve the offending limb index in the wire error.
        let index = fields[4..7]
            .iter()
            .zip([120, 120, 16])
            .position(|(limb, bits)| limb.into_bigint().num_bits() > bits)
            .expect("invalid U256 limb");
        MarshalingError::InvalidMintLimb(index)
    })?;

    Ok(PublicInputs {
        chain_id,
        root: words[1].into(),
        nullifier: words[2].into(),
        note_owner,
        mint_units,
        change_commitment: words[7].into(),
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
        assert_eq!(decoded.note_owner, Address::from([0x22; 20]));
        assert_eq!(
            decoded.mint_units,
            U256::from(40) + (U256::from(1) << 200) + (U256::from(u16::MAX) << 240)
        );
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

        for index in 0..3 {
            let mut invalid_limb = valid_words();
            invalid_limb[4 + index][6] = 1; // 2^200, wider than u128.
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
            U256::MAX
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
