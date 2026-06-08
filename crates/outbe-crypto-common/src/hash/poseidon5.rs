//! Single-shot `Poseidon5` over BN254 Fr.
//!
//! Kept for backward compatibility with the pre-Grumpkin ownership
//! formula. The current ownership commitment uses [`super::poseidon3`].

use ark_bn254::Fr;
use outbe_poseidon::PoseidonHasher;

use crate::OutbeCryptoError;

/// Single-shot Poseidon5 over five `Fr` values.
pub fn poseidon5(a: Fr, b: Fr, c: Fr, d: Fr, e: Fr) -> Result<Fr, OutbeCryptoError> {
    let mut poseidon = outbe_poseidon::Poseidon::<Fr>::new_circom(5)
        .map_err(|err| OutbeCryptoError::Poseidon(format!("new_circom(5): {err}")))?;
    poseidon
        .hash(&[a, b, c, d, e])
        .map_err(|err| OutbeCryptoError::Poseidon(format!("hash: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon5_deterministic() {
        let inputs = (
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
        );
        let a = poseidon5(inputs.0, inputs.1, inputs.2, inputs.3, inputs.4).unwrap();
        let b = poseidon5(inputs.0, inputs.1, inputs.2, inputs.3, inputs.4).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn poseidon5_order_sensitive() {
        let a = poseidon5(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
        )
        .unwrap();
        let b = poseidon5(
            Fr::from(5u64),
            Fr::from(4u64),
            Fr::from(3u64),
            Fr::from(2u64),
            Fr::from(1u64),
        )
        .unwrap();
        assert_ne!(a, b);
    }
}
