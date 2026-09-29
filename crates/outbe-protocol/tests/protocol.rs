//! Production hash formulas, entity ordering, and signer origins.

use alloy_primitives::hex;
use ark_ff::One;
use ark_std::UniformRand;

use outbe_protocol::primitive::{exchange, hash, signature};
use outbe_protocol::protocol::entity::{Entity, Owned};
use outbe_protocol::protocol::key::{NftSigner, Signer};
use outbe_protocol::{codec, Error, Fr};

struct TestNft {
    id: Fr,
    owner: Fr,
    fields: Vec<Fr>,
}

impl Entity for TestNft {
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

impl Owned for TestNft {
    fn owner(&self) -> Result<Fr, Error> {
        Ok(self.owner)
    }
}

#[test]
fn owner_and_entity_hash_bind_their_inputs() {
    let mut rng = ark_std::test_rng();
    let (_, pk) = signature::keypair(&mut rng);
    let nonce = Fr::rand(&mut rng);
    let owner = hash::derive_owner(&pk, nonce).unwrap();
    assert_ne!(owner, hash::derive_owner(&pk, nonce + Fr::one()).unwrap());

    let mut entity = TestNft {
        id: owner,
        owner,
        fields: vec![Fr::from(978u64), Fr::from(1_000u64), Fr::from(42u64)],
    };
    let original_hash = entity.entity_hash().unwrap();
    assert_eq!(entity.owner().unwrap(), owner);
    entity.fields[1] += Fr::one();
    assert_ne!(original_hash, entity.entity_hash().unwrap());
    entity.fields[1] -= Fr::one();
    entity.id += Fr::one();
    assert_ne!(original_hash, entity.entity_hash().unwrap());
}

#[test]
fn id_body_precedes_entity_body_in_position_order() {
    #[derive(outbe_protocol_derive::Entity)]
    struct Compound {
        #[outbe(body, pos = 1)]
        last: u64,
        #[outbe(id_seed)]
        seed: u64,
        #[outbe(id_body, pos = 1)]
        second_id: u64,
        #[outbe(body, pos = 0)]
        first: u64,
        #[outbe(id_body, pos = 0)]
        first_id: u64,
    }
    let entity = Compound {
        last: 5,
        seed: 1,
        second_id: 3,
        first: 4,
        first_id: 2,
    };
    let first_id = hash::poseidon2(&[Fr::from(1u64), Fr::from(2u64)]).unwrap();
    let id = hash::poseidon2(&[first_id, Fr::from(3u64)]).unwrap();
    let first_body = hash::poseidon2(&[id, Fr::from(4u64)]).unwrap();
    let expected = hash::poseidon2(&[first_body, Fr::from(5u64)]).unwrap();
    assert_eq!(entity.id().unwrap(), id);
    assert_eq!(entity.entity_hash().unwrap(), expected);
}

#[test]
fn consent_box_reconstructs_only_for_the_recipient() {
    let mut rng = ark_std::test_rng();
    let (consent_sk, consent_pk) = exchange::random_keypair(&mut rng);
    let (server_seed, opaque_pk) = Signer::issue_for_remote(&mut rng, &consent_pk).unwrap();
    let client = Signer::from_exchange(&consent_sk, &opaque_pk, server_seed.nonce).unwrap();
    assert_eq!(client.public_key(), server_seed.pk);
    assert_eq!(
        client.owner_seed().derive_owner().unwrap(),
        server_seed.derive_owner().unwrap()
    );
    let payload = hash::signing_payload(Fr::from(7u64), server_seed.nonce, Fr::from(9u64)).unwrap();
    let sig = client.sign(&mut rng, payload).unwrap();
    assert!(signature::verify(&server_seed.pk, payload, &sig));

    let (other_sk, _) = exchange::random_keypair(&mut rng);
    let wrong = Signer::from_exchange(&other_sk, &opaque_pk, server_seed.nonce).unwrap();
    assert_ne!(wrong.public_key(), server_seed.pk);
    let wrong_sig = wrong.sign(&mut rng, payload).unwrap();
    assert!(!signature::verify(&server_seed.pk, payload, &wrong_sig));
}

#[test]
fn local_signer_signs_for_its_owner() {
    let mut rng = ark_std::test_rng();
    let local = Signer::local(&mut rng).unwrap();
    let payload =
        hash::signing_payload(Fr::from(7u64), local.owner_seed().nonce, Fr::from(9u64)).unwrap();
    let sig = local.sign(&mut rng, payload).unwrap();
    assert!(signature::verify(&local.owner_seed().pk, payload, &sig));
    assert!(!signature::verify(
        &local.owner_seed().pk,
        payload + Fr::one(),
        &sig
    ));
}

#[test]
fn binding_matches_the_tribute_vector_and_separates_chains() {
    // outbe-l2-claims/tests/tribute.rs at upstream commit 2d494e9.
    let binding = hash::binding(&[1; 20], &[2; 32], 19_280_501, 57_005).unwrap();
    assert_eq!(
        codec::field_to_be_bytes(&binding),
        hex::decode("1fa0a96020985973a74705b5e7b6f54f3c3f9b9ca1d0de200c93566e2eb73402").unwrap()
    );
    assert_ne!(
        binding,
        hash::binding(&[1; 20], &[2; 32], 19_280_501, 57_006).unwrap()
    );
    assert_ne!(
        binding,
        hash::binding(&[1; 20], &[2; 32], 19_280_502, 57_005).unwrap()
    );
}
