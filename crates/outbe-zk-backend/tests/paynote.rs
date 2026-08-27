//! Real barretenberg prove→verify round-trip for the canonical Paynote circuit.
//!
//! The formulas are reimplemented off-circuit (here and in `common`) on purpose:
//! the point of the test is that Rust-computed public inputs match the
//! in-circuit ones, which only means something if the two derivations are
//! independent.

mod common;

use ark_ff::PrimeField;

use outbe_zk_canonical::noir::paynote::{Paynote, PublicInputs, Witness};

use common::{address, hash_tagged, AuthPath, Fr};

const PAYNOTE: &str = "OUTBE_PAYNOTE";

fn note_serial(spend_key: Fr) -> Fr {
    hash_tagged(PAYNOTE, "NOTE_SN", &[spend_key])
}

fn note_commitment(chain_id: u64, serial: Fr, asset: Fr, amount: u128) -> Fr {
    hash_tagged(
        PAYNOTE,
        "COMMITMENT",
        &[Fr::from(chain_id), serial, asset, Fr::from(amount)],
    )
}

/// Derived from the commitment, not the serial — so every leaf has exactly one
/// nullifier, and `chain_id` needs no separate input.
fn nullifier(commitment: Fr, spend_key: Fr) -> Fr {
    hash_tagged(PAYNOTE, "NULLIFIER", &[commitment, spend_key])
}

fn single_leaf_path(chain_id: u64) -> AuthPath {
    common::single_leaf_path(PAYNOTE, chain_id)
}

#[test]
fn paynote_partial_spend_prove_verify_round_trip() {
    let chain_id = 31_337u64;
    let asset = address([0xa0; 20]);
    let spender = address([0x33; 20]);
    let spend_key = Fr::from(17u64);

    // Above 2^64, so a u64 amount anywhere in the pipeline would truncate.
    let note_amount = (1u128 << 80) + 100;
    let spend_amount = (1u128 << 80) + 40;

    let serial = note_serial(spend_key);
    let commitment = note_commitment(chain_id, serial, asset, note_amount);
    let auth_path = single_leaf_path(chain_id);
    let root = common::root_from_path(PAYNOTE, commitment, 0, &auth_path);
    let spent_nullifier = nullifier(commitment, spend_key);

    // The change note inherits the same asset, so it stays spendable in the
    // same token.
    let next_key = hash_tagged(PAYNOTE, "CHANGE_KEY", &[spend_key, spent_nullifier]);
    let change_commitment = note_commitment(
        chain_id,
        note_serial(next_key),
        asset,
        note_amount - spend_amount,
    );

    let public = PublicInputs {
        chain_id,
        root,
        nullifier: spent_nullifier,
        asset,
        spender,
        spend_amount,
        change_commitment,
    };
    let witness = Witness {
        note_amount,
        note_spend_key: spend_key,
        leaf_index: 0,
        auth_path,
    };

    common::assert_round_trip::<Paynote>(
        &witness,
        &public,
        &[
            (
                "a different spend amount",
                PublicInputs {
                    spend_amount: spend_amount + 1,
                    ..public.clone()
                },
            ),
            (
                "a different asset",
                PublicInputs {
                    asset: address([0x22; 20]),
                    ..public.clone()
                },
            ),
            // Binding `spender` is what stops a mempool observer lifting the
            // proof and redirecting the payment.
            (
                "a different spender",
                PublicInputs {
                    spender: address([0x44; 20]),
                    ..public.clone()
                },
            ),
        ],
    );
}

/// `asset` crosses the ABI as an `EthAddress` struct, so `from_field` -- and its
/// range check -- never runs on it. `asset.validate()` in `main` is the only
/// thing left holding the 160-bit bound.
///
/// Every other constraint here is satisfied (serial, commitment, root and
/// nullifier are all derived from the oversized asset), so `validate` is the
/// sole reason this must fail. Delete that call and this test goes green.
#[test]
fn oversized_asset_is_rejected() {
    let mut bytes = [0u8; 21];
    bytes[0] = 1; // exactly 2^160 — one bit too wide for an address
    let asset = Fr::from_be_bytes_mod_order(&bytes);

    let chain_id = 31_337u64;
    let spend_key = Fr::from(17u64);
    let serial = note_serial(spend_key);
    let commitment = note_commitment(chain_id, serial, asset, 100);
    let auth_path = single_leaf_path(chain_id);
    let root = common::root_from_path(PAYNOTE, commitment, 0, &auth_path);

    let public = PublicInputs {
        chain_id,
        root,
        nullifier: nullifier(commitment, spend_key),
        asset,
        spender: address([0x33; 20]),
        spend_amount: 100,
        change_commitment: Fr::from(0u64),
    };
    let witness = Witness {
        note_amount: 100,
        note_spend_key: spend_key,
        leaf_index: 0,
        auth_path,
    };

    common::assert_unprovable::<Paynote>(
        &witness,
        &public,
        "an asset of 2^160 must fail EthAddress::validate in-circuit",
    );
}
