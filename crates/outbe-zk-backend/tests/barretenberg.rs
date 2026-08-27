//! Real barretenberg prove→verify round-trips.
//!
//! Generates actual UltraHonkKeccak proofs from genuine witnesses and verifies
//! them through the FFI backend — the full on-device path. Run with
//! `cargo test -p outbe-zk-backend --test barretenberg`.

use ark_ff::UniformRand;

use outbe_protocol::error::Error;
use outbe_protocol::primitive::signature::SignatureScheme;
use outbe_protocol::protocol::entity::{Entity, Owned};
use outbe_protocol::protocol::imt::Imt;
use outbe_protocol::protocol::key::{NftSecret, Signer};
use outbe_protocol::protocol::zk::{ProofGenerator, ProofVerifier};
use outbe_protocol::{OutbeV1, Suite};
use outbe_zk_backend::barretenberg::Barretenberg;
use outbe_zk_canonical::full::{full_circuit_domain, FullProvable};
use outbe_zk_canonical::noir::full_proof::FullProof;
use outbe_zk_canonical::noir::ownership_proof::OwnershipProof;
use outbe_zk_canonical::ownership::Provable;
use outbe_zk_canonical::INCLUSION_DEPTH;

type Fr = <OutbeV1 as Suite>::Field;

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
fn ownership_prove_verify_round_trip() {
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

    // Generate a real UltraHonkKeccak proof and verify it.
    let proof = ProofGenerator::<OutbeV1, OwnershipProof>::generate(
        &Barretenberg::default(),
        &witness,
        &public,
    )
    .expect("bb prove");
    assert!(
        ProofVerifier::<OutbeV1, OwnershipProof>::verify(&Barretenberg::default(), &public, &proof)
            .unwrap(),
        "valid proof must verify"
    );

    // Verifying against a different claim (tampered binding) must fail.
    let mut wrong = public.clone();
    wrong.binding_hash += Fr::from(1u64);
    assert!(
        !ProofVerifier::<OutbeV1, OwnershipProof>::verify(&Barretenberg::default(), &wrong, &proof)
            .unwrap(),
        "proof must not verify against a different public input"
    );
}

#[test]
fn full_proof_prove_verify_round_trip() {
    let mut rng = ark_std::test_rng();
    let (sk, pk) = <OutbeV1 as Suite>::Signature::keypair(&mut rng);
    let nonce = Fr::rand(&mut rng);
    let owner = OutbeV1::derive_owner(&pk, nonce).unwrap();
    let binding = OutbeV1::binding(&[3u8; 20], &[4u8; 32], 99).unwrap();
    let td = TestNft {
        id: owner,
        owner,
        fields: vec![Fr::from(978u64), Fr::from(100u64)],
    };
    let signer = Signer::from_secret(NftSecret::new(sk), nonce).unwrap();
    let tree = Imt::<OutbeV1>::new(full_circuit_domain(), INCLUSION_DEPTH).unwrap();
    let path = tree.empty_inclusion_path(0);
    let (witness, public) = td
        .derive_full_witness(&mut rng, &signer, binding, &path)
        .unwrap();

    let proof =
        ProofGenerator::<OutbeV1, FullProof>::generate(&Barretenberg::default(), &witness, &public)
            .expect("bb prove");
    assert!(
        ProofVerifier::<OutbeV1, FullProof>::verify(&Barretenberg::default(), &public, &proof)
            .unwrap(),
        "valid full proof must verify"
    );
}
