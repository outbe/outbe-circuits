//! Single-shot `Poseidon4` over BN254 Fr.
//!
//! Available for four-input commitments. Like `poseidon5`, this is
//! **not** the iterated Poseidon2 of [`crate::hash::OutbeHasher`].

use ark_bn254::Fr;
use outbe_poseidon::PoseidonHasher;

use crate::OutbeCryptoError;

/// Single-shot Poseidon4 over four `Fr` values.
pub fn poseidon4(a: Fr, b: Fr, c: Fr, d: Fr) -> Result<Fr, OutbeCryptoError> {
    let mut poseidon = outbe_poseidon::Poseidon::<Fr>::new_circom(4)
        .map_err(|err| OutbeCryptoError::Poseidon(format!("new_circom(4): {err}")))?;
    poseidon
        .hash(&[a, b, c, d])
        .map_err(|err| OutbeCryptoError::Poseidon(format!("hash: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon4_deterministic() {
        let a = poseidon4(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        )
        .unwrap();
        let b = poseidon4(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn poseidon4_order_sensitive() {
        let a = poseidon4(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        )
        .unwrap();
        let b = poseidon4(
            Fr::from(4u64),
            Fr::from(3u64),
            Fr::from(2u64),
            Fr::from(1u64),
        )
        .unwrap();
        assert_ne!(a, b);
    }
}
