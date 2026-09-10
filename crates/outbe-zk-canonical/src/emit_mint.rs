//! Emit mint combined-proof layout and public-input decoding.

pub mod hash;

use outbe_protocol::protocol::shielded_pool::ShieldedPool;
use outbe_protocol::{OutbeV1, Suite};

#[cfg(feature = "alloy")]
pub use crate::noir::emit_mint::alloy::{decode_public_inputs, PublicInputs, Witness};

/// Cryptographic suite used by Emit.
pub type EmitSuite = OutbeV1;
pub type Field = <EmitSuite as Suite>::Field;

pub type Pool = ShieldedPool<OutbeV1>;

/// In-memory commitment tree for Emit clients.
pub type Tree = outbe_protocol::protocol::imt::Imt<EmitSuite>;

pub use crate::noir::emit_mint::{COMBINED_LEN, PROOF_WORDS, PUBLIC_INPUT_COUNT};

#[cfg(all(test, feature = "alloy"))]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256};
    use outbe_protocol::error::Error;

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
    fn generated_decoder_preserves_noncanonical_errors() {
        for (index, bits, expected) in [
            (0, 64, "u64"),
            (3, 160, "address"),
            (4, 120, "uint256 limbs"),
            (5, 120, "uint256 limbs"),
            (6, 16, "uint256 limbs"),
        ] {
            let mut proof = combined();
            let start = 4 + index * 32;
            let invalid: U256 = U256::from(1) << bits;
            proof[start..start + 32].copy_from_slice(&invalid.to_be_bytes::<32>());
            assert!(matches!(
                decode_public_inputs(&proof),
                Err(Error::NonCanonical(what)) if what == expected
            ));
        }
        let mut proof = combined();
        proof[4..36].fill(0xff);
        assert!(matches!(
            decode_public_inputs(&proof),
            Err(Error::NonCanonical("public input"))
        ));
    }
}
