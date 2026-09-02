//! Canonical ZK verifier wire marshaling.
//!
//! This module owns the consensus-visible byte layouts shared by the chain and
//! verifier backend. It deliberately does not depend on a circuit registry or a
//! proving backend; callers decode and validate the wire here, compare the
//! public claim with runtime state, then dispatch the unchanged combined proof
//! to their selected verifier.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

const CANONICAL_ABI_OFFSET: u64 = 64;

pub const FULL_PROOF_PUBLIC_INPUT_COUNT: usize = 4;
pub const FULL_PROOF_PROOF_WORDS: usize = 274;
pub const FULL_PROOF_COMBINED_LEN: usize =
    4 + (FULL_PROOF_PUBLIC_INPUT_COUNT + FULL_PROOF_PROOF_WORDS) * 32;

pub const EMIT_MINT_PUBLIC_INPUT_COUNT: usize = 8;
pub const EMIT_MINT_PROOF_WORDS: usize = 250;
pub const EMIT_MINT_COMBINED_LEN: usize =
    4 + (EMIT_MINT_PUBLIC_INPUT_COUNT + EMIT_MINT_PROOF_WORDS) * 32;

pub const PAYNOTE_PUBLIC_INPUT_COUNT: usize = 9;
pub const PAYNOTE_PROOF_WORDS: usize = 250;
pub const PAYNOTE_COMBINED_LEN: usize = 4 + (PAYNOTE_PUBLIC_INPUT_COUNT + PAYNOTE_PROOF_WORDS) * 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofMarshalingError {
    #[error("zk_verify: input too short ({0} < 64 bytes)")]
    InputTooShort(usize),
    #[error("zk_verify: malformed ABI input ({0})")]
    MalformedAbi(&'static str),
    #[error("zk_verify: combined proof is too short ({0} < 4 bytes)")]
    CombinedProofTooShort(usize),
    #[error("zk_verify: combined proof public input count is {actual}, expected {expected}")]
    WrongPublicInputCount { expected: usize, actual: usize },
    #[error("zk_verify: combined proof public inputs are truncated ({actual} < {expected} bytes)")]
    TruncatedPublicInputs { expected: usize, actual: usize },
    #[error("zk_verify: public input at index {0} is not a canonical BN254 field element")]
    NonCanonicalPublicInput(usize),
    #[error("zk_verify: combined proof length is {actual} bytes, expected {expected}")]
    WrongCombinedProofLength { expected: usize, actual: usize },
    #[error("zk_verify: emit chain ID word is not a right-aligned uint64")]
    InvalidEmitChainId,
    #[error("zk_verify: emit owner word exceeds the 160-bit address bound")]
    InvalidEmitOwner,
    #[error("zk_verify: emit mint limb {0} is outside its canonical range")]
    InvalidEmitMintLimb(usize),
}

/// Canonical decoding of `abi.encode(bytes32 circuit_hash, bytes proof)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyCall<'a> {
    pub circuit_hash: [u8; 32],
    pub combined_proof: &'a [u8],
}

/// Public claim carried by `outbe.full_proof@1.1.0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullProofPublicInputs {
    pub derived_owner: [u8; 32],
    pub nft_hash: [u8; 32],
    pub binding_hash: [u8; 32],
    pub merkle_root: [u8; 32],
}

/// Public claim carried by `outbe.paynote@1.1.0` in circuit order.
#[cfg(feature = "alloy")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayNotePublicInputs {
    pub chain_id: u64,
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub asset: alloy_primitives::Address,
    pub spender: alloy_primitives::Address,
    pub spend_amount: alloy_primitives::U256,
    pub change_commitment: [u8; 32],
}

/// Public claim carried by `outbe.emit.mint@1.5.0` in circuit order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmitMintPublicInputs {
    pub chain_id: u64,
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub note_owner: [u8; 20],
    /// Three little-endian noir-bignum limbs with radix `2^120`.
    pub mint_units: [u128; 3],
    pub change_commitment: [u8; 32],
}

pub fn decode_verify_call(input: &[u8]) -> Result<VerifyCall<'_>, ProofMarshalingError> {
    if input.len() < 64 {
        return Err(ProofMarshalingError::InputTooShort(input.len()));
    }

    let mut circuit_hash = [0u8; 32];
    circuit_hash.copy_from_slice(&input[..32]);

    let offset = read_u64_be_padded(&input[32..64])
        .ok_or(ProofMarshalingError::MalformedAbi("offset too large"))?;
    if offset != CANONICAL_ABI_OFFSET {
        return Err(ProofMarshalingError::MalformedAbi("non-canonical offset"));
    }
    let offset = usize::try_from(offset)
        .map_err(|_| ProofMarshalingError::MalformedAbi("offset too large"))?;
    let header_end = offset
        .checked_add(32)
        .ok_or(ProofMarshalingError::MalformedAbi("offset overflow"))?;
    if input.len() < header_end {
        return Err(ProofMarshalingError::MalformedAbi("offset past end"));
    }

    let length = read_u64_be_padded(&input[offset..header_end])
        .ok_or(ProofMarshalingError::MalformedAbi("length too large"))?;
    let length = usize::try_from(length)
        .map_err(|_| ProofMarshalingError::MalformedAbi("length too large"))?;
    let data_end = header_end
        .checked_add(length)
        .ok_or(ProofMarshalingError::MalformedAbi("length overflow"))?;
    if input.len() < data_end {
        return Err(ProofMarshalingError::MalformedAbi("payload truncated"));
    }

    let padding = (32 - length % 32) % 32;
    let encoded_end = data_end
        .checked_add(padding)
        .ok_or(ProofMarshalingError::MalformedAbi("padding overflow"))?;
    if input.len() != encoded_end {
        return Err(ProofMarshalingError::MalformedAbi(
            "non-canonical total length",
        ));
    }
    if input[data_end..encoded_end].iter().any(|byte| *byte != 0) {
        return Err(ProofMarshalingError::MalformedAbi("non-zero padding"));
    }

    Ok(VerifyCall {
        circuit_hash,
        combined_proof: &input[header_end..data_end],
    })
}

pub fn decode_full_proof_public_inputs(
    combined_proof: &[u8],
) -> Result<FullProofPublicInputs, ProofMarshalingError> {
    let words = decode_public_words::<FULL_PROOF_PUBLIC_INPUT_COUNT>(
        combined_proof,
        FULL_PROOF_COMBINED_LEN,
    )?;
    Ok(FullProofPublicInputs {
        derived_owner: words[0],
        nft_hash: words[1],
        binding_hash: words[2],
        merkle_root: words[3],
    })
}

#[cfg(feature = "alloy")]
pub fn decode_paynote_public_inputs(
    combined_proof: &[u8],
) -> Result<PayNotePublicInputs, ProofMarshalingError> {
    let words =
        decode_public_words::<PAYNOTE_PUBLIC_INPUT_COUNT>(combined_proof, PAYNOTE_COMBINED_LEN)?;

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
    let spend_amount = alloy_primitives::U256::from_be_bytes(
        crate::codec::u256_from_limbs_be(limbs).expect("validated canonical U256 limbs"),
    );

    Ok(PayNotePublicInputs {
        chain_id,
        root: words[1],
        nullifier: words[2],
        asset,
        spender,
        spend_amount,
        change_commitment: words[8],
    })
}

pub fn decode_emit_mint_public_inputs(
    combined_proof: &[u8],
) -> Result<EmitMintPublicInputs, ProofMarshalingError> {
    let words = decode_public_words::<EMIT_MINT_PUBLIC_INPUT_COUNT>(
        combined_proof,
        EMIT_MINT_COMBINED_LEN,
    )?;

    let chain_id = read_u64_be_padded(&words[0]).ok_or(ProofMarshalingError::InvalidEmitChainId)?;
    if words[3][..12].iter().any(|byte| *byte != 0) {
        return Err(ProofMarshalingError::InvalidEmitOwner);
    }
    let mut note_owner = [0u8; 20];
    note_owner.copy_from_slice(&words[3][12..]);

    let mut mint_units = [0u128; 3];
    for (index, (limb, word)) in mint_units.iter_mut().zip(&words[4..7]).enumerate() {
        *limb =
            read_u128_be_padded(word).ok_or(ProofMarshalingError::InvalidEmitMintLimb(index))?;
    }
    for (index, limb) in mint_units.iter().copied().enumerate() {
        let limit = if index < 2 { 1u128 << 120 } else { 1u128 << 16 };
        if limb >= limit {
            return Err(ProofMarshalingError::InvalidEmitMintLimb(index));
        }
    }

    Ok(EmitMintPublicInputs {
        chain_id,
        root: words[1],
        nullifier: words[2],
        note_owner,
        mint_units,
        change_commitment: words[7],
    })
}

fn decode_public_words<const N: usize>(
    combined_proof: &[u8],
    expected_len: usize,
) -> Result<[[u8; 32]; N], ProofMarshalingError> {
    let header = combined_proof
        .get(..4)
        .ok_or(ProofMarshalingError::CombinedProofTooShort(
            combined_proof.len(),
        ))?;
    let count = u32::from_be_bytes(header.try_into().expect("four-byte slice")) as usize;
    if count != N {
        return Err(ProofMarshalingError::WrongPublicInputCount {
            expected: N,
            actual: count,
        });
    }
    let public_end = 4 + N * 32;
    if combined_proof.len() < public_end {
        return Err(ProofMarshalingError::TruncatedPublicInputs {
            expected: public_end,
            actual: combined_proof.len(),
        });
    }
    if combined_proof.len() != expected_len {
        return Err(ProofMarshalingError::WrongCombinedProofLength {
            expected: expected_len,
            actual: combined_proof.len(),
        });
    }

    let mut words = [[0u8; 32]; N];
    let (public_words, remainder) = combined_proof[4..public_end].as_chunks::<32>();
    debug_assert!(remainder.is_empty());
    for (index, word) in public_words.iter().enumerate() {
        words[index] = *word;
        if !is_canonical_field_word(&words[index]) {
            return Err(ProofMarshalingError::NonCanonicalPublicInput(index));
        }
    }
    Ok(words)
}

fn read_u64_be_padded(slot: &[u8]) -> Option<u64> {
    if slot.len() != 32 || slot[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(u64::from_be_bytes(slot[24..].try_into().ok()?))
}

fn read_u128_be_padded(slot: &[u8]) -> Option<u128> {
    if slot.len() != 32 || slot[..16].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(u128::from_be_bytes(slot[16..].try_into().ok()?))
}

#[cfg(feature = "alloy")]
fn read_address_be_padded(slot: &[u8]) -> Option<alloy_primitives::Address> {
    if slot.len() != 32 || slot[..12].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(&slot[12..]);
    Some(alloy_primitives::Address::from(address))
}

fn is_canonical_field_word(word: &[u8; 32]) -> bool {
    let field = Fr::from_be_bytes_mod_order(word);
    let bytes = field.into_bigint().to_bytes_be();
    let mut canonical = [0u8; 32];
    canonical[32 - bytes.len()..].copy_from_slice(&bytes);
    canonical == *word
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn abi_encode(circuit_hash: [u8; 32], proof: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + proof.len() + 31);
        out.extend_from_slice(&circuit_hash);
        out.extend_from_slice(&u64_word(64));
        out.extend_from_slice(&u64_word(proof.len() as u64));
        out.extend_from_slice(proof);
        out.resize(out.len() + (32 - proof.len() % 32) % 32, 0);
        out
    }

    fn valid_emit_words() -> [[u8; 32]; EMIT_MINT_PUBLIC_INPUT_COUNT] {
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

    #[cfg(feature = "alloy")]
    fn valid_paynote_words() -> [[u8; 32]; PAYNOTE_PUBLIC_INPUT_COUNT] {
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
    fn verify_call_decodes_canonical_solidity_abi() {
        let hash = [0xabu8; 32];
        let proof = [0xcdu8; 35];
        let encoded = abi_encode(hash, &proof);
        let decoded = decode_verify_call(&encoded).unwrap();
        assert_eq!(decoded.circuit_hash, hash);
        assert_eq!(decoded.combined_proof, proof);
    }

    #[test]
    fn verify_call_rejects_short_and_non_canonical_offsets() {
        assert_eq!(
            decode_verify_call(&[0u8; 32]),
            Err(ProofMarshalingError::InputTooShort(32))
        );
        for offset in [65u64, 96, u64::MAX] {
            let mut encoded = abi_encode([0; 32], &[0; 32]);
            encoded[56..64].copy_from_slice(&offset.to_be_bytes());
            assert_eq!(
                decode_verify_call(&encoded),
                Err(ProofMarshalingError::MalformedAbi("non-canonical offset"))
            );
        }
    }

    #[test]
    fn verify_call_rejects_truncation_padding_and_trailing_bytes() {
        let mut truncated = abi_encode([0; 32], &[0xcd; 35]);
        truncated.truncate(100);
        assert_eq!(
            decode_verify_call(&truncated),
            Err(ProofMarshalingError::MalformedAbi("payload truncated"))
        );

        let mut non_zero_padding = abi_encode([0; 32], &[0xcd; 35]);
        *non_zero_padding.last_mut().unwrap() = 1;
        assert_eq!(
            decode_verify_call(&non_zero_padding),
            Err(ProofMarshalingError::MalformedAbi("non-zero padding"))
        );

        let mut trailing = abi_encode([0; 32], &[0xcd; 32]);
        trailing.extend_from_slice(&[0; 32]);
        assert_eq!(
            decode_verify_call(&trailing),
            Err(ProofMarshalingError::MalformedAbi(
                "non-canonical total length"
            ))
        );
    }

    #[test]
    fn full_proof_inputs_decode_in_circuit_order() {
        let words = [
            field_word(11),
            field_word(22),
            field_word(33),
            field_word(44),
        ];
        let proof = combined(words, FULL_PROOF_PROOF_WORDS);
        let decoded = decode_full_proof_public_inputs(&proof).unwrap();
        assert_eq!(decoded.derived_owner, words[0]);
        assert_eq!(decoded.nft_hash, words[1]);
        assert_eq!(decoded.binding_hash, words[2]);
        assert_eq!(decoded.merkle_root, words[3]);
    }

    #[test]
    fn full_proof_rejects_wrong_count_length_and_field_encoding() {
        let mut wrong_count = combined([[0; 32]; 4], FULL_PROOF_PROOF_WORDS);
        wrong_count[..4].copy_from_slice(&3u32.to_be_bytes());
        assert!(matches!(
            decode_full_proof_public_inputs(&wrong_count),
            Err(ProofMarshalingError::WrongPublicInputCount { .. })
        ));

        let wrong_length = combined([[0; 32]; 4], FULL_PROOF_PROOF_WORDS - 1);
        assert!(matches!(
            decode_full_proof_public_inputs(&wrong_length),
            Err(ProofMarshalingError::WrongCombinedProofLength { .. })
        ));

        let mut words = [[0; 32]; 4];
        let modulus = Fr::MODULUS.to_bytes_be();
        words[2][32 - modulus.len()..].copy_from_slice(&modulus);
        let non_canonical = combined(words, FULL_PROOF_PROOF_WORDS);
        assert_eq!(
            decode_full_proof_public_inputs(&non_canonical),
            Err(ProofMarshalingError::NonCanonicalPublicInput(2))
        );
    }

    #[test]
    fn marshaling_errors_keep_chain_visible_text() {
        let cases = [
            (
                ProofMarshalingError::InputTooShort(3),
                "zk_verify: input too short (3 < 64 bytes)",
            ),
            (
                ProofMarshalingError::MalformedAbi("bad offset"),
                "zk_verify: malformed ABI input (bad offset)",
            ),
            (
                ProofMarshalingError::CombinedProofTooShort(2),
                "zk_verify: combined proof is too short (2 < 4 bytes)",
            ),
            (
                ProofMarshalingError::WrongPublicInputCount {
                    expected: 9,
                    actual: 8,
                },
                "zk_verify: combined proof public input count is 8, expected 9",
            ),
            (
                ProofMarshalingError::TruncatedPublicInputs {
                    expected: 292,
                    actual: 100,
                },
                "zk_verify: combined proof public inputs are truncated (100 < 292 bytes)",
            ),
            (
                ProofMarshalingError::NonCanonicalPublicInput(5),
                "zk_verify: public input at index 5 is not a canonical BN254 field element",
            ),
            (
                ProofMarshalingError::WrongCombinedProofLength {
                    expected: 8_292,
                    actual: 8_260,
                },
                "zk_verify: combined proof length is 8260 bytes, expected 8292",
            ),
            (
                ProofMarshalingError::InvalidEmitChainId,
                "zk_verify: emit chain ID word is not a right-aligned uint64",
            ),
            (
                ProofMarshalingError::InvalidEmitOwner,
                "zk_verify: emit owner word exceeds the 160-bit address bound",
            ),
            (
                ProofMarshalingError::InvalidEmitMintLimb(1),
                "zk_verify: emit mint limb 1 is outside its canonical range",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[cfg(feature = "alloy")]
    #[test]
    fn paynote_inputs_decode_current_u256_layout() {
        let words = valid_paynote_words();
        let proof = combined(words, PAYNOTE_PROOF_WORDS);
        let decoded = decode_paynote_public_inputs(&proof).unwrap();
        assert_eq!(decoded.chain_id, 31_337);
        assert_eq!(decoded.root, words[1]);
        assert_eq!(decoded.nullifier, words[2]);
        assert_eq!(decoded.asset, alloy_primitives::Address::from([0x11; 20]));
        assert_eq!(decoded.spender, alloy_primitives::Address::from([0x22; 20]));
        assert_eq!(decoded.spend_amount, alloy_primitives::U256::MAX);
        assert_eq!(decoded.change_commitment, words[8]);
        assert_eq!(proof.len(), PAYNOTE_COMBINED_LEN);
    }

    #[cfg(feature = "alloy")]
    #[test]
    fn paynote_rejects_short_wrong_count_and_wrong_length() {
        assert_eq!(
            decode_paynote_public_inputs(&[0u8; 3]),
            Err(ProofMarshalingError::CombinedProofTooShort(3))
        );

        let mut wrong_count = combined(valid_paynote_words(), PAYNOTE_PROOF_WORDS);
        wrong_count[..4].copy_from_slice(&8u32.to_be_bytes());
        assert_eq!(
            decode_paynote_public_inputs(&wrong_count),
            Err(ProofMarshalingError::WrongPublicInputCount {
                expected: PAYNOTE_PUBLIC_INPUT_COUNT,
                actual: 8,
            })
        );

        let wrong_length = combined(valid_paynote_words(), PAYNOTE_PROOF_WORDS - 1);
        assert_eq!(
            decode_paynote_public_inputs(&wrong_length),
            Err(ProofMarshalingError::WrongCombinedProofLength {
                expected: PAYNOTE_COMBINED_LEN,
                actual: PAYNOTE_COMBINED_LEN - 32,
            })
        );
    }

    #[cfg(feature = "alloy")]
    #[test]
    fn paynote_rejects_oversized_addresses_and_limbs_by_word_index() {
        let mut invalid_address = valid_paynote_words();
        invalid_address[3][11] = 1;
        assert_eq!(
            decode_paynote_public_inputs(&combined(invalid_address, PAYNOTE_PROOF_WORDS)),
            Err(ProofMarshalingError::NonCanonicalPublicInput(3))
        );

        for (word_index, value) in [(5, 1u128 << 120), (6, 1u128 << 120), (7, 1u128 << 16)] {
            let mut invalid_limb = valid_paynote_words();
            invalid_limb[word_index] = u128_word(value);
            assert_eq!(
                decode_paynote_public_inputs(&combined(invalid_limb, PAYNOTE_PROOF_WORDS)),
                Err(ProofMarshalingError::NonCanonicalPublicInput(word_index))
            );
        }
    }

    #[test]
    fn emit_inputs_decode_current_u256_layout() {
        let words = valid_emit_words();
        let proof = combined(words, EMIT_MINT_PROOF_WORDS);
        let decoded = decode_emit_mint_public_inputs(&proof).unwrap();
        assert_eq!(decoded.chain_id, 31_337);
        assert_eq!(decoded.root, words[1]);
        assert_eq!(decoded.nullifier, words[2]);
        assert_eq!(decoded.note_owner, [0x22; 20]);
        assert_eq!(decoded.mint_units, [40, 1u128 << 80, (1u128 << 16) - 1]);
        assert_eq!(decoded.change_commitment, words[7]);
        assert_eq!(proof.len(), EMIT_MINT_COMBINED_LEN);
    }

    #[test]
    fn emit_rejects_wrong_count_and_length() {
        let mut wrong_count = combined(valid_emit_words(), EMIT_MINT_PROOF_WORDS);
        wrong_count[..4].copy_from_slice(&7u32.to_be_bytes());
        assert!(matches!(
            decode_emit_mint_public_inputs(&wrong_count),
            Err(ProofMarshalingError::WrongPublicInputCount { .. })
        ));

        let wrong_length = combined(valid_emit_words(), EMIT_MINT_PROOF_WORDS + 1);
        assert!(matches!(
            decode_emit_mint_public_inputs(&wrong_length),
            Err(ProofMarshalingError::WrongCombinedProofLength { .. })
        ));
    }

    #[test]
    fn emit_rejects_invalid_chain_owner_and_limbs() {
        let mut invalid_chain = valid_emit_words();
        invalid_chain[0][23] = 1;
        assert_eq!(
            decode_emit_mint_public_inputs(&combined(invalid_chain, EMIT_MINT_PROOF_WORDS)),
            Err(ProofMarshalingError::InvalidEmitChainId)
        );

        let mut invalid_owner = valid_emit_words();
        invalid_owner[3][11] = 1;
        assert_eq!(
            decode_emit_mint_public_inputs(&combined(invalid_owner, EMIT_MINT_PROOF_WORDS)),
            Err(ProofMarshalingError::InvalidEmitOwner)
        );

        for (index, value) in [(0, 1u128 << 120), (1, 1u128 << 120), (2, 1u128 << 16)] {
            let mut invalid_limb = valid_emit_words();
            invalid_limb[4 + index] = u128_word(value);
            assert_eq!(
                decode_emit_mint_public_inputs(&combined(invalid_limb, EMIT_MINT_PROOF_WORDS)),
                Err(ProofMarshalingError::InvalidEmitMintLimb(index))
            );
        }
    }

    #[test]
    fn emit_accepts_maximum_canonical_u256_limbs() {
        let mut words = valid_emit_words();
        words[4] = u128_word((1u128 << 120) - 1);
        words[5] = u128_word((1u128 << 120) - 1);
        words[6] = u128_word((1u128 << 16) - 1);
        assert_eq!(
            decode_emit_mint_public_inputs(&combined(words, EMIT_MINT_PROOF_WORDS))
                .unwrap()
                .mint_units,
            [(1u128 << 120) - 1, (1u128 << 120) - 1, (1u128 << 16) - 1,]
        );
    }
}
