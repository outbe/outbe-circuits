//! Shared off-circuit mirrors of the in-circuit hash / Merkle formulas, plus the
//! prove→verify assertions, for the note-circuit round-trip tests.
//!
//! The formulas are reimplemented off-circuit on purpose: the point of the tests
//! is that Rust-computed public inputs match the in-circuit ones, which only
//! means something if the two derivations are independent.

use ark_ff::PrimeField;

use outbe_protocol::primitive::hash::FieldHasher;
use outbe_protocol::protocol::zk::{Circuit, CircuitId, ProofGenerator, ProofVerifier};
use outbe_protocol::{OutbeV1, Suite};
use outbe_zk_backend::barretenberg::Barretenberg;
use outbe_zk_canonical::INCLUSION_DEPTH;

pub type Fr = <OutbeV1 as Suite>::Field;
pub type AuthPath = [Fr; INCLUSION_DEPTH];

fn h2(left: Fr, right: Fr) -> Fr {
    <<OutbeV1 as Suite>::Hash as FieldHasher<Fr>>::hash(&[left, right]).unwrap()
}

fn h3(first: Fr, second: Fr, third: Fr) -> Fr {
    <<OutbeV1 as Suite>::Hash as FieldHasher<Fr>>::hash(&[first, second, third]).unwrap()
}

fn ascii_field(value: &str) -> Fr {
    Fr::from_be_bytes_mod_order(value.as_bytes())
}

/// One 20-byte address = one big-endian field element. Must agree with
/// `EthAddress::from_field` on the circuit side.
pub fn address(bytes: [u8; 20]) -> Fr {
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Mirror of `outbe_circuit_core::tags::tag`: a base purpose tag folded with
/// the domain that owns it.
fn tag(domain: &str, base: &str) -> Fr {
    h2(ascii_field(domain), ascii_field(base))
}

/// Domain-tagged, length-prefixed hash of a value list.
pub fn hash_tagged(domain: &str, base: &str, values: &[Fr]) -> Fr {
    let mut state = h2(tag(domain, base), Fr::from(values.len() as u64));
    for value in values {
        state = h2(state, *value);
    }
    state
}

/// Authentication path for leaf 0 of an otherwise empty tree.
pub fn single_leaf_path(domain: &str, chain_id: u64) -> AuthPath {
    let mut path = [Fr::from(0u64); INCLUSION_DEPTH];
    path[0] = hash_tagged(domain, "EMPTY", &[Fr::from(chain_id)]);
    for level in 1..INCLUSION_DEPTH {
        path[level] = h3(ascii_field(domain), path[level - 1], path[level - 1]);
    }
    path
}

pub fn root_from_path(domain: &str, leaf: Fr, leaf_index: u32, path: &AuthPath) -> Fr {
    let mut current = leaf;
    for (level, sibling) in path.iter().copied().enumerate() {
        let is_left = (leaf_index >> level) & 1 == 0;
        current = if is_left {
            h3(ascii_field(domain), current, sibling)
        } else {
            h3(ascii_field(domain), sibling, current)
        };
    }
    current
}

/// Prove, assert the honest claim verifies, then assert each tampered claim —
/// labelled by what it changed — does not.
pub fn assert_round_trip<C>(
    witness: &C::Witness,
    public: &C::PublicInputs,
    tampered: &[(&str, C::PublicInputs)],
) where
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
