//! Emit mint combined-proof layout and public-input decoding.

pub mod hash;

#[cfg(feature = "alloy")]
pub use crate::noir::emit_mint::alloy::{self, Witness};
pub use crate::noir::emit_mint::{decode_public_inputs, encode_combined_proof, PublicInputs};

/// The proving field.
pub type Field = outbe_zk_core::Fr;

pub type Pool = outbe_zk_core::shielded_pool::ShieldedPool;

/// In-memory commitment tree for Emit clients.
pub type Tree = outbe_zk_core::imt::Imt;

pub use crate::noir::emit_mint::{COMBINED_LEN, PROOF_WORDS, PUBLIC_INPUT_COUNT};

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{Field as _, PrimeField};
    use outbe_zk_core::codec::field_to_be_bytes;
    use outbe_zk_core::Error;

    fn combined() -> Vec<u8> {
        let mut proof = (PUBLIC_INPUT_COUNT as u32).to_be_bytes().to_vec();
        for word in [
            Fr::from(31_337),
            Fr::from(102),
            Fr::from(103),
            Fr::from_be_bytes_mod_order(&[0x22; 20]),
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(104),
        ] {
            proof.extend_from_slice(&field_to_be_bytes(&word));
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
                root: Fr::from(102),
                nullifier: Fr::from(103),
                note_owner: Fr::from_be_bytes_mod_order(&[0x22; 20]),
                mint_units: [1, 2, 3],
                change_commitment: Fr::from(104),
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
            let invalid = Fr::from(2).pow([bits]);
            proof[start..start + 32].copy_from_slice(&field_to_be_bytes(&invalid));
            assert!(matches!(
                decode_public_inputs(&proof),
                Err(Error::NonCanonical(what)) if what == expected
            ));
            let mut public = decode_public_inputs(&combined()).unwrap();
            match index {
                3 => public.note_owner = invalid,
                4..=6 => public.mint_units[index - 4] = 1u128 << bits,
                // An out-of-range u64 cannot be constructed in the generic type.
                _ => continue,
            }
            assert!(matches!(
                encode_combined_proof(public, vec![vec![0; 32]; PROOF_WORDS]),
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
