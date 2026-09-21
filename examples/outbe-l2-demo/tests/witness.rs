//! The witness contract, checked without proving.
//!
//! The strongest check here is the ACVM solve: the witness is lowered through
//! `witness_inputs` and run against the *real* committed ACIR, so a successful
//! solve proves three things at once — the witness-index layout is right, the
//! field/byte encoding is right, and the pure-Rust Schnorr signature actually
//! satisfies the in-circuit verifier. It costs no proving and no SRS.

mod common;

use ark_bn254::Fr;

use outbe_l2_demo::{empty_tree, prove_tribute, tree_domain, TributeDemo, DEPTH};
use outbe_zk_backend::witness;
use outbe_zk_core::entity::Entity;
use outbe_zk_core::imt::Imt;
use outbe_zk_core::keys::coords;
use outbe_zk_core::zk::Circuit;
use outbe_zk_core::Error;

#[test]
fn witness_solves_the_real_acir() {
    let mut rng = ark_std::test_rng();
    let f = common::fixture(&mut rng);
    let tree = empty_tree().unwrap();
    let path = tree.empty_inclusion_path(0);
    let (w, public) = prove_tribute(&mut rng, &f.claim, &f.signer, f.binding, &path).unwrap();

    let solved = witness::solved_witness::<TributeDemo>(&w, &public)
        .expect("the tribute witness must satisfy the registered circuit");
    assert!(!solved.is_empty(), "solved witness serializes to bytes");
    assert_eq!(
        witness::public_inputs::<TributeDemo>(&public).len(),
        4,
        "a tribute proof exposes 4 public words"
    );
}

#[test]
fn tampered_signature_fails_to_solve() {
    let mut rng = ark_std::test_rng();
    let f = common::fixture(&mut rng);
    let tree = empty_tree().unwrap();
    let path = tree.empty_inclusion_path(0);
    let (mut w, public) = prove_tribute(&mut rng, &f.claim, &f.signer, f.binding, &path).unwrap();
    w.signature[0] ^= 0xff;

    assert!(
        witness::solved_witness::<TributeDemo>(&w, &public).is_err(),
        "a tampered signature must make the circuit unsatisfiable"
    );
}

/// The prover's contract: public words come from the claim and the signer, the
/// root is recomputed from the path, the index bits are little-endian, and an
/// owner that does not match `(pk, nonce)` is refused before any proving.
#[test]
fn prover_contract_over_the_inclusion_path() {
    let mut rng = ark_std::test_rng();
    let f = common::fixture(&mut rng);

    // Index 0 of an otherwise-empty tree: current-left at every level.
    let tree = empty_tree().unwrap();
    let path = tree.empty_inclusion_path(0);
    let (w, public) = prove_tribute(&mut rng, &f.claim, &f.signer, f.binding, &path).unwrap();

    assert_eq!(public.owner, f.signer.owner_seed().derive_owner().unwrap());
    assert_eq!(public.nft_hash, f.claim.entity_hash().unwrap());
    assert_eq!(public.binding_hash, f.binding);
    assert_eq!(w.merkle_path_siblings.len(), DEPTH);
    assert_eq!(w.merkle_path_indices, [true; DEPTH]);
    assert_eq!(
        public.merkle_root,
        path.root(public.nft_hash).unwrap(),
        "merkle root must be the path resolved over nft_hash"
    );

    // A populated tree must keep the domain, the leaf value and the bit order.
    let mut populated = empty_tree().unwrap();
    populated.append(Fr::from(17u64)).unwrap();
    let index = populated.append(public.nft_hash).unwrap();
    populated.append(Fr::from(23u64)).unwrap();
    let populated_path = populated.inclusion_path(index).unwrap();
    let (pw, pp) =
        prove_tribute(&mut rng, &f.claim, &f.signer, f.binding, &populated_path).unwrap();
    assert_eq!(pp.merkle_root, populated.root());
    assert!(!pw.merkle_path_indices[0], "leaf 1 sits on the right");
    assert!(pw.merkle_path_indices[1..].iter().all(|bit| *bit));
    assert_eq!(
        pw.merkle_path_siblings.as_slice(),
        populated_path.siblings.as_slice()
    );

    // A claim whose stored owner does not match (pk, nonce) is rejected.
    let mut wrong = f.claim.clone();
    wrong.owner = common::word(4242);
    assert!(
        matches!(
            prove_tribute(&mut rng, &wrong, &f.signer, f.binding, &path),
            Err(Error::OwnerMismatch)
        ),
        "owner mismatch was not rejected"
    );

    // A path of another depth or another domain is not this L2's tree.
    let shallow = Imt::new(tree_domain(), Fr::from(0u64), DEPTH - 1).unwrap();
    assert!(prove_tribute(
        &mut rng,
        &f.claim,
        &f.signer,
        f.binding,
        &shallow.empty_inclusion_path(0)
    )
    .is_err());
    let other_domain = Imt::new(Fr::from(1u64), Fr::from(0u64), DEPTH).unwrap();
    assert!(prove_tribute(
        &mut rng,
        &f.claim,
        &f.signer,
        f.binding,
        &other_domain.empty_inclusion_path(0)
    )
    .is_err());
}

/// `witness_inputs` is in ACIR witness-index order and locked to the root ABI:
/// `pk`(2) + `signature`(64) + `nonce`(1) + `merkle_path_siblings`(32) +
/// `merkle_path_indices`(32) + 4 public = 135 leaves. Each signature byte and
/// each path bit takes one witness, and the public tail is exactly the
/// verify-side projection — so the prover and the on-chain verifier read one
/// mapping.
#[test]
fn witness_inputs_layout_is_canonical() {
    let mut rng = ark_std::test_rng();
    let f = common::fixture(&mut rng);
    let tree = empty_tree().unwrap();
    let path = tree.empty_inclusion_path(0);
    let (w, public) = prove_tribute(&mut rng, &f.claim, &f.signer, f.binding, &path).unwrap();

    let v = <TributeDemo as Circuit>::witness_inputs(&w, &public);
    assert_eq!(v.len(), 2 + 64 + 1 + 32 + 32 + 4, "tribute witness arity");

    let (x, y) = coords(&f.signer.owner_seed().pk).unwrap();
    assert_eq!(v[0], x, "Witness(0) = pk.x");
    assert_eq!(v[1], y, "Witness(1) = pk.y");
    assert_eq!(
        v[2],
        Fr::from(w.signature[0] as u64),
        "Witness(2) = signature[0]"
    );
    assert_eq!(
        v[65],
        Fr::from(w.signature[63] as u64),
        "Witness(65) = signature[63]"
    );
    assert_eq!(v[66], w.nonce, "Witness(66) = nonce");
    assert_eq!(
        &v[67..67 + 32],
        w.merkle_path_siblings.as_slice(),
        "Witness(67..99) = merkle_path_siblings"
    );
    assert_eq!(
        v[99],
        Fr::from(w.merkle_path_indices[0] as u64),
        "Witness(99) = merkle_path_indices[0]"
    );
    assert_eq!(
        v[130],
        Fr::from(w.merkle_path_indices[31] as u64),
        "Witness(130) = merkle_path_indices[31]"
    );
    assert_eq!(
        &v[131..],
        <TributeDemo as Circuit>::public_inputs(&public).as_slice(),
        "public tail == public_inputs"
    );
}
