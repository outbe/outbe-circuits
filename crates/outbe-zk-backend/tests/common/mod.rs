//! Shared tree and proving helpers for note-circuit round trips.

use outbe_zk_backend::barretenberg::{Barretenberg, Proof};
use outbe_zk_core::zk::{Circuit, CircuitId, ProofGenerator, ProofVerifier};
use outbe_zk_core::{hash::ascii_field, imt::Imt, shielded_pool::ShieldedPool};

pub type Pool = ShieldedPool;
type Tree = Imt;
pub use outbe_zk_core::Fr;
/// Auth-path length of the `emit_mint` and `paynote` ABIs
/// (`outbe_circuit_core::merkle_tree::DEPTH`).
const DEPTH: usize = 32;
pub type AuthPath = [Fr; DEPTH];

pub fn address(bytes: [u8; 20]) -> Fr {
    outbe_zk_core::codec::field_from_be_bytes(&bytes)
}

/// Raw fields let negative tests construct out-of-range circuit witnesses.
pub fn hash_tagged(domain: &str, base: Fr, values: &[Fr]) -> Fr {
    let tag = Pool::tag(ascii_field(domain), base).unwrap();
    Pool::hash_multi(tag, values).unwrap()
}

pub fn single_leaf_path(domain: &str, chain_id: u64) -> AuthPath {
    let empty = hash_tagged(domain, Pool::tag_empty(), &[Fr::from(chain_id)]);
    let zeros = Tree::empty_roots(ascii_field(domain), empty, DEPTH).unwrap();
    zeros[..DEPTH].try_into().unwrap()
}

pub fn root_from_path(domain: &str, leaf: Fr, leaf_index: u32, path: &AuthPath) -> Fr {
    Tree::root_from_inclusion_path(ascii_field(domain), leaf, u64::from(leaf_index), path).unwrap()
}

/// Prove, assert the honest claim verifies, then assert each tampered claim —
/// labelled by what it changed — does not.
pub fn assert_round_trip<C>(
    witness: &C::Witness,
    public: &C::PublicInputs,
    tampered: &[(&str, C::PublicInputs)],
) -> Proof
where
    C: Circuit + CircuitId,
{
    let backend = Barretenberg::default();
    let proof = ProofGenerator::<C>::generate(&backend, witness, public).expect("proof generation");
    assert!(
        ProofVerifier::<C>::verify(&backend, public, &proof).unwrap(),
        "valid {} proof must verify",
        C::LABEL
    );
    for (changed, claim) in tampered {
        assert!(
            !ProofVerifier::<C>::verify(&backend, claim, &proof).unwrap(),
            "proof must not verify for {changed}"
        );
    }
    proof
}

/// Assert the witness/claim pair is unsatisfiable — proving must fail in-circuit.
pub fn assert_unprovable<C>(witness: &C::Witness, public: &C::PublicInputs, why: &str)
where
    C: Circuit + CircuitId,
{
    assert!(
        ProofGenerator::<C>::generate(&Barretenberg::default(), witness, public).is_err(),
        "{why}"
    );
}
