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
//! Generic over any [`CircuitSuite`] (the BN254/Grumpkin cycle the noir circuit
//! is compiled for) — so `OutbeV1` and any future same-cycle suite both work.
//!
//! [`Entity`]: outbe_protocol::protocol::entity::Entity
//! [`Owned`]: outbe_protocol::protocol::entity::Owned

use ark_std::rand::Rng;

use outbe_protocol::error::Error;
use outbe_protocol::primitive::curve::{coords, Affine};
use outbe_protocol::primitive::exchange::KeyExchange;
use outbe_protocol::primitive::signature::SignatureScheme;
use outbe_protocol::protocol::entity::{Entity, Owned};
use outbe_protocol::protocol::key::{NftSigner, Signer};
use outbe_protocol::protocol::zk::{ProofGenerator, ProofVerifier};
use outbe_protocol::Suite;

use crate::noir::ownership_proof::{OwnershipProof, PublicInputs, Witness};
use crate::noir::EmbeddedCurvePoint;
use crate::CircuitSuite;

/// The in-protocol Schnorr check over a built ownership pair, independent of
/// any ZK proof. Reconstructs the payload from `(nft_hash, nonce, binding)`
/// and verifies the 64-byte `s ‖ e` signature against `pk` — the same
/// signature the circuit verifies. Aggregation uses this to confirm each slot
/// (padding included).
pub fn verify_signature<S: CircuitSuite>(
    public: &PublicInputs,
    nonce: S::Field,
    pk: &Affine<S::Curve>,
    signature: &[u8; 64],
) -> Result<bool, Error> {
    let payload = S::signing_payload(public.nft_hash, nonce, public.binding_hash)?;
    Ok(<S as Suite>::Signature::verify(pk, payload, signature))
}

/// NFT extension: an owned entity can build the ownership circuit witness +
/// public inputs (and, given a backend, a proof). Named in the style of
/// [`Owned`]; blanket-implemented for every owned entity of a [`CircuitSuite`].
///
/// [`Owned`]: outbe_protocol::protocol::entity::Owned
pub trait Provable<S: CircuitSuite>: Entity<S> + Owned<S> {
    /// Build + sign the ownership witness, returning the generated
    /// `(Witness, PublicInputs)` pair. Recomputes `owner` from `(pk, nonce)`
    /// and rejects a mismatch — the same constraint the circuit enforces,
    /// caught at witness-build time.
    fn derive_ownership_witness<R, K>(
        &self,
        rng: &mut R,
        signer: &K,
        binding: S::Field,
    ) -> Result<(Witness, PublicInputs), Error>
    where
        R: Rng,
        K: NftSigner<S>,
    {
        let seed = signer.owner_seed();
        let owner = S::derive_owner(&seed.pk, seed.nonce)?;
        if owner != self.owner()? {
            return Err(Error::OwnerMismatch);
        }
        let nft_hash = self.entity_hash()?;
        let payload = S::signing_payload(nft_hash, seed.nonce, binding)?;
        let signature = signer.sign(rng, payload)?;

        let (x, y) = coords::<S::Curve>(&seed.pk)?;
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
    fn prove_ownership_via_consent<R, X>(
        &self,
        rng: &mut R,
        consent_sk: &X::Secret,
        opaque_pk: &X::Public,
        nonce: S::Field,
        binding: S::Field,
    ) -> Result<(Witness, PublicInputs), Error>
    where
        R: Rng,
        X: KeyExchange<S::Field>,
    {
        let signer = Signer::<S>::from_exchange::<X>(consent_sk, opaque_pk, nonce)?;
        self.derive_ownership_witness(rng, &signer, binding)
    }

    /// Build the witness + public inputs and hand them to a ZK
    /// proof-generation backend.
    fn generate_ownership_proof<R, K, G>(
        &self,
        rng: &mut R,
        signer: &K,
        binding: S::Field,
        generator: &G,
    ) -> Result<G::Proof, Error>
    where
        R: Rng,
        K: NftSigner<S>,
        G: ProofGenerator<S, OwnershipProof>,
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
        binding: S::Field,
        generator: &G,
        verifier: &V,
    ) -> Result<bool, Error>
    where
        R: Rng,
        K: NftSigner<S>,
        G: ProofGenerator<S, OwnershipProof>,
        V: ProofVerifier<S, OwnershipProof, Proof = G::Proof>,
    {
        let (witness, public) = self.derive_ownership_witness(rng, signer, binding)?;
        let proof = generator.generate(&witness, &public)?;
        verifier.verify(&public, &proof)
    }
}

impl<S: CircuitSuite, E: Entity<S> + Owned<S> + ?Sized> Provable<S> for E {}

/// NFT extension: verify an ownership proof. Accepts the public inputs and
/// proof and defers to a [`ProofVerifier`] backend.
pub trait Verifiable<S: CircuitSuite> {
    /// Verify `proof` against `public` using `verifier`.
    fn verify_ownership<V>(
        verifier: &V,
        public: &PublicInputs,
        proof: &V::Proof,
    ) -> Result<bool, Error>
    where
        V: ProofVerifier<S, OwnershipProof>,
    {
        verifier.verify(public, proof)
    }
}

impl<S: CircuitSuite, E: Entity<S> + ?Sized> Verifiable<S> for E {}
