//! The concrete core formulas: the owner commitment, entity hashing, the
//! submission binding, and local key self-issuance.
//!
//! Every formula here is concrete over `ark_bn254::Fr`.

use ark_ff::One;
use ark_std::rand::Rng;
use ark_std::UniformRand;

use outbe_zk_core::entity::Entity;
use outbe_zk_core::error::Error;
use outbe_zk_core::hash;
use outbe_zk_core::keys::{self, Signer};
use outbe_zk_core::Fr;

/// Minimal entity for exercising the core: a stored id and a flat body. The
/// real entity types live in consumer crates.
struct TestNft {
    id: Fr,
    fields: Vec<Fr>,
}

impl Entity for TestNft {
    fn id(&self) -> Result<Fr, Error> {
        Ok(self.id)
    }
    fn encode_body(&self, out: &mut Vec<Fr>) -> Result<(), Error> {
        out.extend_from_slice(&self.fields);
        Ok(())
    }
}

fn sample_nft<R: Rng>(rng: &mut R, owner: Fr) -> TestNft {
    TestNft {
        id: owner,
        fields: vec![
            Fr::from(978u64),   // currency
            Fr::from(1_000u64), // base
            Fr::from(42u64),    // micro
            Fr::rand(rng),      // su_id
            Fr::rand(rng),      // su_id
        ],
    }
}

#[test]
fn core_formulas() {
    let mut rng = ark_std::test_rng();

    // --- owner commitment: deterministic + sensitive to nonce ---
    let (_sk, pk) = keys::keypair(&mut rng);
    let nonce = Fr::rand(&mut rng);
    let owner = hash::derive_owner(&pk, nonce).unwrap();
    assert_eq!(
        owner,
        hash::derive_owner(&pk, nonce).unwrap(),
        "owner not deterministic"
    );
    let owner2 = hash::derive_owner(&pk, nonce + Fr::one()).unwrap();
    assert_ne!(owner, owner2, "owner not sensitive to nonce");

    // --- entity hash: deterministic + sensitive to body ---
    let td = sample_nft(&mut rng, owner);
    let h1 = td.entity_hash().unwrap();
    assert_eq!(
        h1,
        td.entity_hash().unwrap(),
        "entity hash not deterministic"
    );
    let td_other = sample_nft(&mut rng, owner); // different random suIds
    assert_ne!(
        h1,
        td_other.entity_hash().unwrap(),
        "entity hash not sensitive to body"
    );

    local_issuance(&mut rng);
}

/// Local self-issuance: the only remaining NFT key origin.
fn local_issuance(rng: &mut impl Rng) {
    // The stored seed pk matches the key the signer holds …
    let local = Signer::local(rng).unwrap();
    assert_eq!(
        local.secret().public_key().unwrap(),
        local.owner_seed().pk,
        "local: pk mismatch"
    );
    // … and a second call draws an independent key + nonce.
    let other = Signer::local(rng).unwrap();
    assert_ne!(
        other.owner_seed().pk,
        local.owner_seed().pk,
        "local: keys must not repeat"
    );
    assert_ne!(
        other.owner_seed().nonce,
        local.owner_seed().nonce,
        "local: nonces must not repeat"
    );
}

/// The signing payload is reachable and order-sensitive — the three elements
/// are a frozen preimage.
#[test]
fn signing_payload_is_order_sensitive() {
    let (a, b, c) = (Fr::from(1u64), Fr::from(2u64), Fr::from(3u64));
    assert_eq!(
        hash::signing_payload(a, b, c).unwrap(),
        hash::signing_payload(a, b, c).unwrap()
    );
    assert_ne!(
        hash::signing_payload(a, b, c).unwrap(),
        hash::signing_payload(c, b, a).unwrap()
    );
}
