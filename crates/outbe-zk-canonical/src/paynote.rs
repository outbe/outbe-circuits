//! Paynote combined-proof layout and public-input decoding.

pub mod hash;

use outbe_protocol::protocol::shielded_pool::ShieldedPool;
use outbe_protocol::{OutbeV1, Suite};

#[cfg(feature = "alloy")]
pub use crate::noir::paynote::alloy::{decode_public_inputs, PublicInputs};
pub use crate::noir::paynote::{COMBINED_LEN, PROOF_WORDS, PUBLIC_INPUT_COUNT};

/// Cryptographic suite used by Paynote.
pub type PayNoteSuite = OutbeV1;
pub type Field = <PayNoteSuite as Suite>::Field;

pub type Pool = ShieldedPool<OutbeV1>;

/// In-memory commitment tree for Paynote clients.
pub type Tree = outbe_protocol::protocol::imt::Imt<PayNoteSuite>;

#[cfg(all(test, feature = "alloy"))]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256};
    use outbe_protocol::protocol::zkproof::ProofMarshalingError;

    fn combined() -> Vec<u8> {
        let mut proof = (PUBLIC_INPUT_COUNT as u32).to_be_bytes().to_vec();
        for word in [
            U256::from(31_337),
            U256::from(202),
            U256::from(203),
            U256::from_be_slice(&[0x11; 20]),
            U256::from_be_slice(&[0x22; 20]),
            U256::from(1),
            U256::from(2),
            U256::from(3),
            U256::from(204),
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
                root: B256::from(U256::from(202)),
                nullifier: B256::from(U256::from(203)),
                asset: Address::from([0x11; 20]),
                owner: Address::from([0x22; 20]),
                // Distinct limbs catch reversed order and shifted ABI offsets.
                spend_amount: U256::from(1) | (U256::from(2) << 120) | (U256::from(3) << 240),
                change_commitment: B256::from(U256::from(204)),
            }
        );
    }

    #[test]
    fn generated_decoder_reports_the_offending_word() {
        for (index, bits) in [(0, 64), (3, 160), (4, 160), (5, 120), (6, 120), (7, 16)] {
            let mut proof = combined();
            let start = 4 + index * 32;
            let invalid: U256 = U256::from(1) << bits;
            proof[start..start + 32].copy_from_slice(&invalid.to_be_bytes::<32>());
            assert_eq!(
                decode_public_inputs(&proof),
                Err(ProofMarshalingError::NonCanonicalPublicInput(index))
            );
        }
    }
}
