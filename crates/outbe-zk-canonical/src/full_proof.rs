//! FullProof combined-proof layout and public-input decoding.

pub use crate::noir::full_proof::decoded::{decode_public_inputs, PublicInputs};
pub use crate::noir::full_proof::{COMBINED_LEN, PROOF_WORDS, PUBLIC_INPUT_COUNT};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_inputs_preserve_full_proof_names_and_bytes() {
        let words = [11u64, 22, 33, 44].map(|value| {
            let mut word = [0; 32];
            word[24..].copy_from_slice(&value.to_be_bytes());
            word
        });
        let mut proof = (PUBLIC_INPUT_COUNT as u32).to_be_bytes().to_vec();
        proof.extend_from_slice(words.as_flattened());
        proof.resize(COMBINED_LEN, 0);
        assert_eq!(
            decode_public_inputs(&proof).unwrap(),
            PublicInputs {
                derived_owner: words[0],
                nft_hash: words[1],
                binding_hash: words[2],
                merkle_root: words[3],
            }
        );
    }
}
