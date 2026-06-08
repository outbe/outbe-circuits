//! Witness builders for circuit-level tests + benches.
//!
//! The Grumpkin keypair / Schnorr-signing primitives live in
//! [`crate::schnorr_grumpkin`] (production module); this module wires
//! them into convenience builders that produce a fully-populated
//! `OwnershipWitness` / `FullProofWitness` from a `(GrumpkinKey,
//! nonce)` pair and an `OwnableNFT + HashableNFT`.
//!
//! Regular `pub mod` rather than `cfg(test)` / feature-gated so that
//! integration tests (`tests/*.rs`) and benches (`benches/*.rs`) --
//! which compile against this crate as if it were any downstream
//! consumer -- can use it without Cargo gymnastics. Production
//! proving paths in the wallet stack call the equivalent
//! `outbe-integrations-shared::witness` builders.
//!
//! Witness semantics match sec. 4.2 of the privacy-preserving L2
//! spec: signature is over `Poseidon2(nft_hash, nonce).to_be_bytes()`
//! and `nft_hash` lives inside `OwnershipPublicInputs`.

use ark_bn254::Fr;

use outbe_crypto_common::merkle::MerklePathElement;
use outbe_crypto_common::witness::{
    FullProofPrivateInputs, FullProofPublicInputs, FullProofWitness, HashableNFT, OwnableNFT,
    OwnershipPrivateInputs, OwnershipPublicInputs, OwnershipWitness,
};

// Re-export the schnorr/grumpkin primitives so existing callers
// (`testing::random_grumpkin_key`, `testing::fr_to_be32`, etc.) keep
// working. `fr_to_le32` stays re-exported for callers that still
// need LE bytes for non-Outbe interop, even though the witness
// builders moved to BE in v0.3.0.
pub use crate::schnorr_grumpkin::{
    derive_grumpkin_public_key, fr_to_be32, fr_to_le32, random_grumpkin_key, schnorr_sign_be,
    GrumpkinKey,
};

/// Compute the owner commitment from a Grumpkin key and a nonce.
/// Thin wrapper over `outbe_crypto_common::ownership::compute_ownership` so
/// test code doesn't have to import outbe-poseidon directly.
pub fn ownership_from_grumpkin_key(key: &GrumpkinKey, nonce: Fr) -> anyhow::Result<Fr> {
    outbe_crypto_common::ownership::compute_ownership_grumpkin(key.pk_x, key.pk_y, nonce)
        .map_err(|e| anyhow::anyhow!("compute_ownership_grumpkin: {e}"))
}

/// Build an `OwnershipWitness` per sec. 4.2.
pub fn build_ownership_witness<T: OwnableNFT + HashableNFT>(
    nft: &T,
    key: &GrumpkinKey,
    nonce: Fr,
) -> anyhow::Result<OwnershipWitness> {
    let ownership_fr = nft.ownership();
    let ownership = fr_to_be32(&ownership_fr);
    let nonce_bytes = fr_to_be32(&nonce);

    let nft_hash_fr = nft.hash().map_err(|e| anyhow::anyhow!("nft hash: {e}"))?;
    let nft_hash = fr_to_be32(&nft_hash_fr);

    let prehash_fr = outbe_crypto_common::hash::poseidon2(nft_hash_fr, nonce)
        .map_err(|e| anyhow::anyhow!("poseidon2(nft_hash, nonce): {e}"))?;
    let signature = schnorr_sign_be(&key.sk_bytes, &prehash_fr)?;

    Ok(OwnershipWitness {
        private_inputs: OwnershipPrivateInputs {
            nonce: nonce_bytes,
            public_key_x: fr_to_be32(&key.pk_x),
            public_key_y: fr_to_be32(&key.pk_y),
        },
        public_inputs: OwnershipPublicInputs {
            ownership,
            nft_hash,
            signature,
        },
    })
}

/// Build a `FullProofWitness` per sec. 4.2 -- same ownership shape as
/// [`build_ownership_witness`], composed with a Merkle inclusion
/// against the same `nft_hash`.
pub fn build_full_proof_witness<T: OwnableNFT + HashableNFT>(
    nft: &T,
    key: &GrumpkinKey,
    nonce: Fr,
    merkle_path: &[MerklePathElement],
) -> anyhow::Result<FullProofWitness> {
    let ownership_fr = nft.ownership();
    let ownership = fr_to_be32(&ownership_fr);
    let nonce_bytes = fr_to_be32(&nonce);

    let nft_hash_fr = nft.hash().map_err(|e| anyhow::anyhow!("nft hash: {e}"))?;
    let nft_hash = fr_to_be32(&nft_hash_fr);

    let prehash_fr = outbe_crypto_common::hash::poseidon2(nft_hash_fr, nonce)
        .map_err(|e| anyhow::anyhow!("poseidon2(nft_hash, nonce): {e}"))?;
    let signature = schnorr_sign_be(&key.sk_bytes, &prehash_fr)?;

    let merkle_root_fr = outbe_crypto_common::merkle::compute_merkle_root(
        &nft_hash_fr,
        merkle_path,
        outbe_crypto_common::merkle::SPARSE_MERKLE_PATH_DEPTH,
    )
    .map_err(|e| anyhow::anyhow!("merkle root: {e}"))?;
    let merkle_root = fr_to_be32(&merkle_root_fr);

    Ok(FullProofWitness {
        private_inputs: FullProofPrivateInputs {
            ownership: OwnershipPrivateInputs {
                nonce: nonce_bytes,
                public_key_x: fr_to_be32(&key.pk_x),
                public_key_y: fr_to_be32(&key.pk_y),
            },
            merkle_path: merkle_path.to_vec(),
        },
        public_inputs: FullProofPublicInputs {
            ownership: OwnershipPublicInputs {
                ownership,
                nft_hash,
                signature,
            },
            merkle_root,
        },
    })
}
