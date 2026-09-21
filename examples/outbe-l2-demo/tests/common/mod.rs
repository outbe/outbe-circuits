//! One tribute draft, signed by one key, bound to one caller — the shape every
//! test here starts from. Built through [`TributeDraft::claim`] rather than by
//! hand, so the projection an L2 implementer copies is itself under test.

#![allow(dead_code)] // each test file uses a subset

use alloy_primitives::{B256, U256};
use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_std::rand::Rng;

use outbe_l2_demo::draft::{DraftState, SpendingUnit, TributeDraft};
use outbe_l2_zk_canonical::claims::tribute::{binding, TributeDraftClaim};
use outbe_zk_core::codec::field_to_b256;
use outbe_zk_core::hash::derive_owner;
use outbe_zk_core::keys::{keypair, NftSecret, Signer};

/// The test chain this demo root is registered under.
pub const L2_CHAIN_ID: u64 = 57005;
/// The host L1 the offer is made on.
pub const HOST_CHAIN_ID: u64 = 31337;
/// The caller `binding_hash` is tied to.
pub const SENDER: [u8; 20] = [0x11; 20];

/// A `B256` that is safely below `FR_MODULUS`.
pub fn word(value: u64) -> B256 {
    B256::from(U256::from(value))
}

pub struct Fixture {
    pub claim: TributeDraftClaim,
    pub signer: Signer,
    pub binding: Fr,
    pub nonce: Fr,
}

/// A draft owned by a fresh key, projected onto the claim and bound to
/// [`SENDER`] on [`HOST_CHAIN_ID`] for [`L2_CHAIN_ID`].
pub fn fixture<R: Rng>(rng: &mut R) -> Fixture {
    let (sk, pk) = keypair(rng);
    let nonce = Fr::rand(rng);
    let owner = derive_owner(&pk, nonce).expect("derive owner");
    let id = word(0xd1a5);
    let draft = TributeDraft {
        id,
        owner: field_to_b256(&owner).expect("owner fits"),
        worldwide_day: 20_263,
        currency: 978,
        // 1_000.000042 — a whole-unit part and a 10^-6 remainder.
        amount_micros: 1_000_000_042,
        spending_units: vec![
            SpendingUnit {
                id: word(99),
                batch: 7,
            },
            SpendingUnit {
                id: word(7),
                batch: 7,
            },
        ],
        state: DraftState::Open,
        created_at: 1_750_000_000,
        note: "L2-only bookkeeping; never hashed".into(),
    };
    Fixture {
        claim: draft.claim().expect("project the draft onto the claim"),
        signer: Signer::from_secret(NftSecret::new(sk), nonce).expect("signer"),
        binding: binding(&SENDER, &id.0, HOST_CHAIN_ID, L2_CHAIN_ID).expect("binding"),
        nonce,
    }
}
