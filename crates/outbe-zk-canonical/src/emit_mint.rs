//! Emit mint combined-proof layout and public-input decoding.

pub mod hash;

use outbe_protocol::protocol::shielded_pool::ShieldedPool;
use outbe_protocol::protocol::zkproof::ProofMarshalingError as WireMarshalingError;
use outbe_protocol::{OutbeV1, Suite};

#[cfg(feature = "alloy")]
pub use crate::noir::emit_mint::alloy::{decode_public_inputs, PublicInputs};

/// Cryptographic suite used by Emit.
pub type EmitSuite = OutbeV1;
pub type Field = <EmitSuite as Suite>::Field;

pub type Pool = ShieldedPool<OutbeV1>;

/// In-memory commitment tree for Emit clients.
pub type Tree = outbe_protocol::protocol::imt::Imt<EmitSuite>;

pub use crate::noir::emit_mint::{COMBINED_LEN, PROOF_WORDS, PUBLIC_INPUT_COUNT};

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

#[cfg(all(test, feature = "alloy"))]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256};

    fn combined() -> Vec<u8> {
        let mut proof = (PUBLIC_INPUT_COUNT as u32).to_be_bytes().to_vec();
        for word in [
            U256::from(31_337),
            U256::from(102),
            U256::from(103),
            U256::from_be_slice(&[0x22; 20]),
            U256::from(1),
            U256::from(2),
            U256::from(3),
            U256::from(104),
        ] {
            proof.extend_from_slice(&word.to_be_bytes::<32>());
        }
        proof.resize(COMBINED_LEN, 0);
        proof
    }

    #[test]
    fn generated_alloy_inputs_follow_abi_order() {
        assert_eq!(
            decode_public_inputs(&combined()).unwrap(),
            PublicInputs {
                chain_id: 31_337,
                root: B256::from(U256::from(102)),
                nullifier: B256::from(U256::from(103)),
                note_owner: Address::from([0x22; 20]),
                mint_units: U256::from(1) | (U256::from(2) << 120) | (U256::from(3) << 240),
                change_commitment: B256::from(U256::from(104)),
            }
        );
    }

    #[test]
    fn generated_decoder_preserves_emit_errors() {
        for (index, bits, expected) in [
            (0, 64, MarshalingError::InvalidChainId),
            (3, 160, MarshalingError::InvalidOwner),
            (4, 120, MarshalingError::InvalidMintLimb(0)),
            (5, 120, MarshalingError::InvalidMintLimb(1)),
            (6, 16, MarshalingError::InvalidMintLimb(2)),
        ] {
            let mut proof = combined();
            let start = 4 + index * 32;
            let invalid: U256 = U256::from(1) << bits;
            proof[start..start + 32].copy_from_slice(&invalid.to_be_bytes::<32>());
            assert_eq!(decode_public_inputs(&proof), Err(expected));
        }
        // Noncanonical field encodings remain wire errors, not InvalidChainId.
        let mut proof = combined();
        proof[4..36].fill(0xff);
        assert_eq!(
            decode_public_inputs(&proof),
            Err(MarshalingError::Wire(
                WireMarshalingError::NonCanonicalPublicInput(0)
            ))
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
