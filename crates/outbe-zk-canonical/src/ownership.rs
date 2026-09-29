//! §4.2 ownership statement, wired to the build-generated noir circuit.
//!
//! The witness ([`Witness`]) and public-input ([`PublicInputs`]) types — and
//! the [`OwnershipProof`] circuit marker — are generated from the vendored
//! `ownership_proof` noir circuit (see [`crate::noir`]). This module supplies
//! the *builder* ([`Provable::derive_ownership_witness`]) that turns an owned
//! entity + signer into the generated `(Witness, PublicInputs)` pair, the
//! in-protocol Schnorr check, and the prove/verify round-trips over the core
//! ZK seams.
//!
//! [`Entity`]: outbe_protocol::protocol::entity::Entity
//! [`Owned`]: outbe_protocol::protocol::entity::Owned

use ark_std::rand::Rng;

use outbe_protocol::error::Error;
use outbe_protocol::primitive::curve::{coords, Affine, Scalar};
use outbe_protocol::primitive::{hash, signature};
use outbe_protocol::protocol::entity::{Entity, Owned};
use outbe_protocol::protocol::key::{NftSigner, Signer};
use outbe_protocol::protocol::zk::{ProofGenerator, ProofVerifier};
use outbe_protocol::Fr;

use crate::noir::ownership_proof::{OwnershipProof, PublicInputs, Witness};
use crate::noir::EmbeddedCurvePoint;

/// The in-protocol Schnorr check over a built ownership pair, independent of
/// any ZK proof. Reconstructs the payload from `(nft_hash, nonce, binding)`
/// and verifies the 64-byte `s ‖ e` signature against `pk` — the same
/// signature the circuit verifies.
pub fn verify_signature(
    public: &PublicInputs,
    nonce: Fr,
    pk: &Affine,
    signature: &[u8; 64],
) -> Result<bool, Error> {
    let payload = hash::signing_payload(public.nft_hash, nonce, public.binding_hash)?;
    Ok(signature::verify(pk, payload, signature))
}

/// NFT extension: an owned entity can build the ownership circuit witness +
/// public inputs (and, given a backend, a proof). Named in the style of
/// [`Owned`]; blanket-implemented for every owned entity.
///
/// [`Owned`]: outbe_protocol::protocol::entity::Owned
pub trait Provable: Entity + Owned {
    /// Build + sign the ownership witness, returning the generated
    /// `(Witness, PublicInputs)` pair. Recomputes `owner` from `(pk, nonce)`
    /// and rejects a mismatch — the same constraint the circuit enforces,
    /// caught at witness-build time.
    fn derive_ownership_witness<R, K>(
        &self,
        rng: &mut R,
        signer: &K,
        binding: Fr,
    ) -> Result<(Witness, PublicInputs), Error>
    where
        R: Rng,
        K: NftSigner,
    {
        let seed = signer.owner_seed();
        let owner = hash::derive_owner(&seed.pk, seed.nonce)?;
        if owner != self.owner()? {
            return Err(Error::OwnerMismatch);
        }
        let nft_hash = self.entity_hash()?;
        let payload = hash::signing_payload(nft_hash, seed.nonce, binding)?;
        let signature = signer.sign(rng, payload)?;

        let (x, y) = coords(&seed.pk)?;
        let witness = Witness {
            pk: EmbeddedCurvePoint { x, y },
            signature,
            nonce: seed.nonce,
        };
        let public = PublicInputs {
            owner,
            nft_hash,
            binding_hash: binding,
        };
        Ok((witness, public))
    }

    /// Prove ownership directly from consent-box material: reconstructs the
    /// NFT secret internally (via [`Signer::from_exchange`]) and signs — the
    /// secret never reaches the caller.
    fn prove_ownership_via_consent<R>(
        &self,
        rng: &mut R,
        consent_sk: &Scalar,
        opaque_pk: &Affine,
        nonce: Fr,
        binding: Fr,
    ) -> Result<(Witness, PublicInputs), Error>
    where
        R: Rng,
    {
        let signer = Signer::from_exchange(consent_sk, opaque_pk, nonce)?;
        self.derive_ownership_witness(rng, &signer, binding)
    }

    /// Build the witness + public inputs and hand them to a ZK
    /// proof-generation backend.
    fn generate_ownership_proof<R, K, G>(
        &self,
        rng: &mut R,
        signer: &K,
        binding: Fr,
        generator: &G,
    ) -> Result<G::Proof, Error>
    where
        R: Rng,
        K: NftSigner,
        G: ProofGenerator<OwnershipProof>,
    {
        let (witness, public) = self.derive_ownership_witness(rng, signer, binding)?;
        generator.generate(&witness, &public)
    }

    /// Full round-trip: build the witness + public inputs, generate a proof,
    /// and verify it. The `where`-clause pins `V::Proof = G::Proof`, so the
    /// generator and verifier must agree on one proof representation.
    fn prove_and_verify<R, K, G, V>(
        &self,
        rng: &mut R,
        signer: &K,
        binding: Fr,
        generator: &G,
        verifier: &V,
    ) -> Result<bool, Error>
    where
        R: Rng,
        K: NftSigner,
        G: ProofGenerator<OwnershipProof>,
        V: ProofVerifier<OwnershipProof, Proof = G::Proof>,
    {
        let (witness, public) = self.derive_ownership_witness(rng, signer, binding)?;
        let proof = generator.generate(&witness, &public)?;
        verifier.verify(&public, &proof)
    }
}

impl<E: Entity + Owned + ?Sized> Provable for E {}

/// NFT extension: verify an ownership proof. Accepts the public inputs and
/// proof and defers to a [`ProofVerifier`] backend.
pub trait Verifiable {
    /// Verify `proof` against `public` using `verifier`.
    fn verify_ownership<V>(
        verifier: &V,
        public: &PublicInputs,
        proof: &V::Proof,
    ) -> Result<bool, Error>
    where
        V: ProofVerifier<OwnershipProof>,
    {
        verifier.verify(public, proof)
    }
}

impl<E: Entity + ?Sized> Verifiable for E {}
