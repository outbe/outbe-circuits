//! Shared tree and proving helpers for note-circuit round trips.

use outbe_protocol::protocol::zk::{Circuit, CircuitId, ProofGenerator, ProofVerifier};
use outbe_protocol::protocol::{imt::Imt, shielded_pool::ShieldedPool};
use outbe_protocol::{OutbeV1, Suite};
use outbe_zk_backend::barretenberg::{Barretenberg, Proof};
use outbe_zk_canonical::INCLUSION_DEPTH;

pub type Pool = ShieldedPool<OutbeV1>;
type Tree = Imt<OutbeV1>;
pub type Fr = <OutbeV1 as Suite>::Field;
pub type AuthPath = [Fr; INCLUSION_DEPTH];

pub fn address(bytes: [u8; 20]) -> Fr {
    outbe_protocol::codec::field_from_be_bytes(&bytes)
}

/// Raw fields let negative tests construct out-of-range circuit witnesses.
pub fn hash_tagged(domain: &str, base: Fr, values: &[Fr]) -> Fr {
    let tag = Pool::tag(OutbeV1::ascii_field(domain), base).unwrap();
    Pool::hash_multi(tag, values).unwrap()
}

pub fn single_leaf_path(domain: &str, chain_id: u64) -> AuthPath {
    let empty = hash_tagged(domain, Pool::tag_empty(), &[Fr::from(chain_id)]);
    let zeros = Tree::empty_roots(OutbeV1::ascii_field(domain), empty, INCLUSION_DEPTH).unwrap();
    zeros[..INCLUSION_DEPTH].try_into().unwrap()
}

pub fn root_from_path(domain: &str, leaf: Fr, leaf_index: u32, path: &AuthPath) -> Fr {
    Tree::root_from_inclusion_path(
        OutbeV1::ascii_field(domain),
        leaf,
        u64::from(leaf_index),
        path,
    )
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
