//! End-to-end validation of the witness mapping against the *real* ACIR.
//!
//! This is the strongest check of the whole "exact mapping": we build an
//! ownership witness with a genuine pure-Rust Schnorr signature, lower it via
//! `witness_inputs`, and run the ACVM solver over the committed bytecode. A
//! successful solve proves three things at once — the witness-index layout is
//! correct, the field/byte encoding is correct, and our Schnorr signature
//! actually satisfies the in-circuit verifier (the solver runs the real
//! blackbox ops). An unsatisfiable witness would surface as `Error::Proof`.

use ark_ff::UniformRand;

use outbe_protocol::error::Error;
use outbe_protocol::primitive::signature::SignatureScheme;
use outbe_protocol::protocol::entity::{Entity, Owned};
use outbe_protocol::protocol::key::{NftSecret, Signer};
use outbe_protocol::{OutbeV1, Suite};
use outbe_zk_backend::witness;
use outbe_zk_canonical::noir::ownership_proof::OwnershipProof;
use outbe_zk_canonical::ownership::Provable;

type Fr = <OutbeV1 as Suite>::Field;

/// Minimal owned entity (the real entity types live in consumer crates).
struct TestNft {
    id: Fr,
    owner: Fr,
    fields: Vec<Fr>,
}

impl Entity<OutbeV1> for TestNft {
    fn id_seed(&self) -> Result<Fr, Error> {
        Ok(self.id)
    }
    fn encode_id_body(&self, _out: &mut Vec<Fr>) -> Result<(), Error> {
        Ok(())
    }
    fn encode_body(&self, out: &mut Vec<Fr>) -> Result<(), Error> {
        out.extend_from_slice(&self.fields);
        Ok(())
    }
}
impl Owned<OutbeV1> for TestNft {
    fn owner(&self) -> Result<Fr, Error> {
        Ok(self.owner)
    }
}

#[test]
fn ownership_witness_solves_real_circuit() {
    let mut rng = ark_std::test_rng();
    let (sk, pk) = <OutbeV1 as Suite>::Signature::keypair(&mut rng);
    let nonce = Fr::rand(&mut rng);
    let owner = OutbeV1::derive_owner(&pk, nonce).unwrap();
    let binding = OutbeV1::binding(&[1u8; 20], &[2u8; 32], 7).unwrap();
    let td = TestNft {
        id: owner,
        owner,
        fields: vec![Fr::from(978u64), Fr::from(100u64)],
    };
    let signer = Signer::from_secret(NftSecret::new(sk), nonce).unwrap();

    let (witness, public) = td
        .derive_ownership_witness(&mut rng, &signer, binding)
        .unwrap();

    // Solve the committed ownership ACIR against our witness. Success proves the
    // mapping is correct AND the Schnorr signature is in-circuit valid.
    let solved = witness::solved_witness::<OutbeV1, OwnershipProof>(&witness, &public)
        .expect("ownership witness must satisfy the real circuit");
    assert!(
        !solved.is_empty(),
        "solved witness should serialize to bytes"
    );

    // The public-input projection is 3 fields (owner, nft_hash, binding).
    let public_inputs = witness::public_inputs::<OutbeV1, OwnershipProof>(&public);
    assert_eq!(public_inputs.len(), 3, "ownership exposes 3 public inputs");
}

#[test]
fn tampered_signature_fails_to_solve() {
    let mut rng = ark_std::test_rng();
    let (sk, pk) = <OutbeV1 as Suite>::Signature::keypair(&mut rng);
    let nonce = Fr::rand(&mut rng);
    let owner = OutbeV1::derive_owner(&pk, nonce).unwrap();
    let binding = OutbeV1::binding(&[1u8; 20], &[2u8; 32], 7).unwrap();
    let td = TestNft {
        id: owner,
        owner,
        fields: vec![Fr::from(1u64)],
    };
    let signer = Signer::from_secret(NftSecret::new(sk), nonce).unwrap();

    let (mut witness, public) = td
        .derive_ownership_witness(&mut rng, &signer, binding)
        .unwrap();
    // Corrupt the signature — the in-circuit verifier must reject it.
    witness.signature[0] ^= 0xff;

    assert!(
        witness::solved_witness::<OutbeV1, OwnershipProof>(&witness, &public).is_err(),
        "a tampered signature must make the circuit unsatisfiable"
    );
}
