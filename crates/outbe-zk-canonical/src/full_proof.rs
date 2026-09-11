//! FullProof combined-proof layout and public-input codecs.

#[cfg(feature = "alloy")]
pub use crate::noir::full_proof::alloy;
pub use crate::noir::full_proof::{
    decode_public_inputs, encode_combined_proof, PublicInputs, COMBINED_LEN, PROOF_WORDS,
    PUBLIC_INPUT_COUNT,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use outbe_protocol::{Codec, OutbeV1};

    #[test]
    fn generated_inputs_preserve_full_proof_names_and_order() {
        let fields = [11u64, 22, 33, 44].map(Fr::from);
        let mut proof = (PUBLIC_INPUT_COUNT as u32).to_be_bytes().to_vec();
        for field in fields {
            proof.extend_from_slice(&OutbeV1::field_to_be_bytes(&field));
        }
        proof.resize(COMBINED_LEN, 0);
        let public = PublicInputs {
            derived_owner: fields[0],
            nft_hash: fields[1],
            binding_hash: fields[2],
            merkle_root: fields[3],
        };
        assert_eq!(decode_public_inputs(&proof).unwrap(), public);
        assert_eq!(
            encode_combined_proof(public, vec![vec![0; 32]; PROOF_WORDS]).unwrap(),
            proof
        );
    }
}
