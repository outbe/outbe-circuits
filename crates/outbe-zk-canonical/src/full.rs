//! Full proof (§4.2 ownership + Merkle inclusion), wired to the build-generated
//! `full_proof` noir circuit.
//!
//! The witness builder ([`FullProvable::derive_full_witness`]) extends the
//! ownership witness with a depth-[`INCLUSION_DEPTH`](crate::INCLUSION_DEPTH)
//! inclusion path against the perpetual TributeDraft commitment tree (the
//! suite-generic [`Imt`](outbe_protocol::protocol::imt::Imt) in the core). The
//! leaf is the entity's `nft_hash` itself — matching the on-chain tree, which
//! stores the entity hash directly — so the inclusion is over the same value
//! the ownership constraint binds. Generic over any [`CircuitSuite`].

use ark_ff::PrimeField;
use ark_std::rand::Rng;

use outbe_protocol::error::Error;
use outbe_protocol::primitive::curve::coords;
use outbe_protocol::protocol::entity::{Entity, Owned};
use outbe_protocol::protocol::imt::InclusionPath;
use outbe_protocol::protocol::key::NftSigner;
use outbe_protocol::protocol::zk::{ProofGenerator, ProofVerifier};

use crate::noir::full_proof::{FullProof, PublicInputs, Witness};
use crate::noir::EmbeddedCurvePoint;
use crate::{CircuitSuite, INCLUSION_DEPTH};

/// Domain prepended to every full-proof commitment-tree inner-node hash.
pub const FULL_CIRCUIT_DOMAIN: &[u8; 18] = b"OUTBE_FULL_CIRCUIT";

/// Full-proof commitment-tree domain as the canonical circuit field.
pub fn full_circuit_domain() -> ark_bn254::Fr {
    ark_bn254::Fr::from_be_bytes_mod_order(FULL_CIRCUIT_DOMAIN)
}

/// NFT extension: an owned entity can build the full-proof witness (ownership +
/// inclusion) and, given a backend, a proof. Blanket-implemented for every
/// owned entity of a [`CircuitSuite`].
pub trait FullProvable<S: CircuitSuite>: Entity<S> + Owned<S> {
    /// Build + sign the full-proof witness: the ownership witness plus the
    /// Merkle inclusion `path` proving `nft_hash` sits in the commitment tree.
    /// The path must use [`FULL_CIRCUIT_DOMAIN`] and have
    /// [`INCLUSION_DEPTH`](crate::INCLUSION_DEPTH) levels. The
    /// `expected_merkle_root` public input is recomputed from the path.
    fn derive_full_witness<R, K>(
        &self,
        rng: &mut R,
        signer: &K,
        binding: S::Field,
        path: &InclusionPath<S>,
    ) -> Result<(Witness, PublicInputs), Error>
    where
        R: Rng,
        K: NftSigner<S>,
    {
        if path.depth() != INCLUSION_DEPTH {
            return Err(Error::Merkle(format!(
                "expected an inclusion path of depth {}, got {}",
                INCLUSION_DEPTH,
                path.depth()
            )));
        }
        if path.domain != full_circuit_domain() {
            return Err(Error::Merkle(
                "inclusion path uses the wrong tree domain".into(),
            ));
        }

        // Ownership: recompute owner from (pk, nonce), reject a mismatch, sign
        // the §4.2 payload — the same constraint the circuit enforces.
        let seed = signer.owner_seed();
        let owner = S::derive_owner(&seed.pk, seed.nonce)?;
        if owner != self.owner()? {
            return Err(Error::OwnerMismatch);
        }
        let nft_hash = self.entity_hash()?;
        let payload = S::signing_payload(nft_hash, seed.nonce, binding)?;
        let signature = signer.sign(rng, payload)?;
        let (x, y) = coords::<S::Curve>(&seed.pk)?;

        // Inclusion: the leaf IS `nft_hash` (the on-chain tree stores the entity
        // hash directly). Recompute the root the circuit will check against.
        let merkle_root = path.root(nft_hash)?;

        let merkle_path_siblings: [S::Field; 32] = path
            .siblings
            .as_slice()
            .try_into()
            .map_err(|_| Error::Merkle("siblings length".into()))?;
        let merkle_path_indices: [bool; 32] = path
            .circuit_indices()
            .try_into()
            .map_err(|_| Error::Merkle("indices length".into()))?;

        let witness = Witness {
            pk: EmbeddedCurvePoint { x, y },
            signature,
            nonce: seed.nonce,
            merkle_path_siblings,
            merkle_path_indices,
        };
        let public = PublicInputs {
            owner,
            nft_hash,
            binding_hash: binding,
            expected_merkle_root: merkle_root,
        };
        Ok((witness, public))
    }

    /// Build the full-proof witness and hand it to a ZK proof-generation backend.
    fn generate_full_proof<R, K, G>(
        &self,
        rng: &mut R,
        signer: &K,
        binding: S::Field,
        path: &InclusionPath<S>,
        generator: &G,
    ) -> Result<G::Proof, Error>
    where
        R: Rng,
        K: NftSigner<S>,
        G: ProofGenerator<S, FullProof>,
    {
        let (witness, public) = self.derive_full_witness(rng, signer, binding, path)?;
        generator.generate(&witness, &public)
    }

    /// Full round-trip: build the witness, generate a proof, and verify it. The
    /// `where`-clause pins `V::Proof = G::Proof`.
    #[allow(clippy::too_many_arguments)]
    fn full_prove_and_verify<R, K, G, V>(
        &self,
        rng: &mut R,
        signer: &K,
        binding: S::Field,
        path: &InclusionPath<S>,
        generator: &G,
        verifier: &V,
    ) -> Result<bool, Error>
    where
        R: Rng,
        K: NftSigner<S>,
        G: ProofGenerator<S, FullProof>,
        V: ProofVerifier<S, FullProof, Proof = G::Proof>,
    {
        let (witness, public) = self.derive_full_witness(rng, signer, binding, path)?;
        let proof = generator.generate(&witness, &public)?;
        verifier.verify(&public, &proof)
    }
}

impl<S: CircuitSuite, E: Entity<S> + Owned<S> + ?Sized> FullProvable<S> for E {}
