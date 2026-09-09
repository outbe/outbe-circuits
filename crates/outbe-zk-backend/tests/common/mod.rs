//! Shared tree and proving helpers for note-circuit round trips.

use outbe_protocol::protocol::zk::{Circuit, CircuitId, ProofGenerator, ProofVerifier};
use outbe_protocol::protocol::{
    imt::Imt,
    shielded_pool::{self, tag_empty},
};
use outbe_protocol::{OutbeV1, Suite};
use outbe_zk_backend::barretenberg::{Barretenberg, Proof};
use outbe_zk_canonical::INCLUSION_DEPTH;

pub type Fr = <OutbeV1 as Suite>::Field;
pub type AuthPath = [Fr; INCLUSION_DEPTH];

pub use outbe_zk_canonical::field::address_field as address;

/// Raw fields let negative tests construct out-of-range circuit witnesses.
pub fn hash_tagged(domain: u128, base: Fr, values: &[Fr]) -> Fr {
    let tag = shielded_pool::tag::<OutbeV1>(Fr::from(domain), base).unwrap();
    shielded_pool::hash_multi::<OutbeV1>(tag, values).unwrap()
}

pub fn single_leaf_path(domain: u128, chain_id: u64) -> AuthPath {
    let empty = hash_tagged(domain, tag_empty::<OutbeV1>(), &[Fr::from(chain_id)]);
    let zeros = Imt::<OutbeV1>::empty_roots(Fr::from(domain), empty, INCLUSION_DEPTH).unwrap();
    zeros[..INCLUSION_DEPTH].try_into().unwrap()
}

pub fn root_from_path(domain: u128, leaf: Fr, leaf_index: u32, path: &AuthPath) -> Fr {
    Imt::<OutbeV1>::root_from_inclusion_path(Fr::from(domain), leaf, u64::from(leaf_index), path)
        .unwrap()
}

/// Prove, assert the honest claim verifies, then assert each tampered claim —
/// labelled by what it changed — does not.
pub fn assert_round_trip<C>(
    witness: &C::Witness,
    public: &C::PublicInputs,
    tampered: &[(&str, C::PublicInputs)],
) -> Proof
where
    C: Circuit<OutbeV1> + CircuitId,
{
    let backend = Barretenberg::default();
    let proof = ProofGenerator::<OutbeV1, C>::generate(&backend, witness, public)
        .expect("proof generation");
    assert!(
        ProofVerifier::<OutbeV1, C>::verify(&backend, public, &proof).unwrap(),
        "valid {} proof must verify",
        C::LABEL
    );
    for (changed, claim) in tampered {
        assert!(
            !ProofVerifier::<OutbeV1, C>::verify(&backend, claim, &proof).unwrap(),
            "proof must not verify for {changed}"
        );
    }
    proof
}

/// Assert the witness/claim pair is unsatisfiable — proving must fail in-circuit.
pub fn assert_unprovable<C>(witness: &C::Witness, public: &C::PublicInputs, why: &str)
where
    C: Circuit<OutbeV1> + CircuitId,
{
    assert!(
        ProofGenerator::<OutbeV1, C>::generate(&Barretenberg::default(), witness, public).is_err(),
        "{why}"
    );
}
