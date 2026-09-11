//! Paynote combined-proof layout and public-input decoding.

pub mod hash;

use outbe_protocol::protocol::shielded_pool::ShieldedPool;
use outbe_protocol::{OutbeV1, Suite};

#[cfg(feature = "alloy")]
pub use crate::noir::paynote::alloy::{self, Witness};
pub use crate::noir::paynote::{decode_public_inputs, encode_combined_proof, PublicInputs};
pub use crate::noir::paynote::{COMBINED_LEN, PROOF_WORDS, PUBLIC_INPUT_COUNT};

/// Cryptographic suite used by Paynote.
pub type PayNoteSuite = OutbeV1;
pub type Field = <PayNoteSuite as Suite>::Field;

pub type Pool = ShieldedPool<OutbeV1>;

/// In-memory commitment tree for Paynote clients.
pub type Tree = outbe_protocol::protocol::imt::Imt<PayNoteSuite>;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{Field as _, PrimeField};
    use outbe_protocol::error::Error;
    use outbe_protocol::Codec;

    fn combined() -> Vec<u8> {
        let mut proof = (PUBLIC_INPUT_COUNT as u32).to_be_bytes().to_vec();
        for word in [
            Fr::from(31_337),
            Fr::from(202),
            Fr::from(203),
            Fr::from_be_bytes_mod_order(&[0x11; 20]),
            Fr::from_be_bytes_mod_order(&[0x22; 20]),
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(204),
        ] {
            proof.extend_from_slice(&OutbeV1::field_to_be_bytes(&word));
        }
        proof.resize(COMBINED_LEN, 0);
        proof
    }

    #[test]
    fn generated_inputs_follow_abi_order() {
        assert_eq!(
            decode_public_inputs(&combined()).unwrap(),
            PublicInputs {
                chain_id: 31_337,
                root: Fr::from(202),
                nullifier: Fr::from(203),
                asset: Fr::from_be_bytes_mod_order(&[0x11; 20]),
                owner: Fr::from_be_bytes_mod_order(&[0x22; 20]),
                // Distinct limbs catch reversed order and shifted ABI offsets.
                spend_amount: [1, 2, 3],
                change_commitment: Fr::from(204),
            }
        );
    }

    #[test]
    fn generated_decoder_preserves_noncanonical_errors() {
        for (index, bits, expected) in [
            (0, 64, "u64"),
            (3, 160, "address"),
            (4, 160, "address"),
            (5, 120, "uint256 limbs"),
            (6, 120, "uint256 limbs"),
            (7, 16, "uint256 limbs"),
        ] {
            let mut proof = combined();
            let start = 4 + index * 32;
            let invalid = Fr::from(2).pow([bits]);
            proof[start..start + 32].copy_from_slice(&OutbeV1::field_to_be_bytes(&invalid));
            assert!(matches!(
                decode_public_inputs(&proof),
                Err(Error::NonCanonical(what)) if what == expected
            ));
            let mut public = decode_public_inputs(&combined()).unwrap();
            match index {
                3 => public.asset = invalid,
                4 => public.owner = invalid,
                5..=7 => public.spend_amount[index - 5] = 1u128 << bits,
                // An out-of-range u64 cannot be constructed in the generic type.
                _ => continue,
            }
            assert!(matches!(
                encode_combined_proof(public, vec![vec![0; 32]; PROOF_WORDS]),
                Err(Error::NonCanonical(what)) if what == expected
            ));
        }
    }
}
