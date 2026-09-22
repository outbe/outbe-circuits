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
use outbe_zk_canonical::demo_tribute::{self, demo_tribute_domain, DemoTributeProvable};
use outbe_zk_canonical::noir::demo_tribute::DemoTribute;
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
    let binding = OutbeV1::binding(&[1u8; 20], &[2u8; 32], 7, 0xdead).unwrap();
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

    // The same proof must fail for another L2, even under the same circuit key.
    let mut wrong = public.clone();
    wrong.binding_hash = OutbeV1::binding(&[1u8; 20], &[2u8; 32], 7, 0xdeae).unwrap();
    assert!(
        !ProofVerifier::<OutbeV1, OwnershipProof>::verify(&Barretenberg::default(), &wrong, &proof)
            .unwrap(),
        "proof must not verify against a different public input"
    );
}

#[test]
fn demo_tribute_prove_verify_round_trip() {
    let mut rng = ark_std::test_rng();
    let (sk, pk) = <OutbeV1 as Suite>::Signature::keypair(&mut rng);
    let nonce = Fr::rand(&mut rng);
    let owner = OutbeV1::derive_owner(&pk, nonce).unwrap();
    let binding = OutbeV1::binding(&[3u8; 20], &[4u8; 32], 99, 0xdead).unwrap();
    let td = TestNft {
        id: owner,
        owner,
        fields: vec![Fr::from(978u64), Fr::from(100u64)],
    };
    let signer = Signer::from_secret(NftSecret::new(sk), nonce).unwrap();
    let tree = Imt::<OutbeV1>::new(demo_tribute_domain(), Fr::from(0u64), INCLUSION_DEPTH).unwrap();
    let path = tree.empty_inclusion_path(0);
    let (witness, public) = td
        .derive_demo_tribute_witness(&mut rng, &signer, binding, &path)
        .unwrap();

    let proof = ProofGenerator::<OutbeV1, DemoTribute>::generate(
        &Barretenberg::default(),
        &witness,
        &public,
    )
    .expect("bb prove");
    assert!(
        ProofVerifier::<OutbeV1, DemoTribute>::verify(&Barretenberg::default(), &public, &proof)
            .unwrap(),
        "valid demo tribute proof must verify"
    );

    let combined = demo_tribute::encode_combined_proof(public.clone(), proof.proof).unwrap();
    assert_eq!(combined.len(), demo_tribute::COMBINED_LEN);
    let decoded = demo_tribute::decode_public_inputs(&combined).unwrap();
    assert_eq!(decoded.derived_owner, owner);
    assert_eq!(decoded.binding_hash, binding);
}
