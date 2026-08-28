//! Real barretenberg prove→verify round-trip for the canonical Emit mint circuit.

mod common;

use ark_ff::PrimeField;

use outbe_zk_canonical::noir::emit_mint::{EmitMint, PublicInputs, Witness};

use common::{address, hash_tagged, AuthPath, Fr};

const EMIT: &str = "OUTBE_EMIT";

fn note_serial(owner: Fr, spend_key: Fr) -> Fr {
    hash_tagged(EMIT, "NOTE_SN", &[owner, spend_key])
}

fn note_commitment(chain_id: u64, serial: Fr, amount: u128) -> Fr {
    hash_tagged(
        EMIT,
        "COMMITMENT",
        &[Fr::from(chain_id), serial, Fr::from(amount)],
    )
}

fn nullifier(commitment: Fr, spend_key: Fr) -> Fr {
    hash_tagged(EMIT, "NULLIFIER", &[commitment, spend_key])
}

fn single_leaf_path(chain_id: u64) -> AuthPath {
    common::single_leaf_path(EMIT, chain_id)
}

#[test]
fn emit_partial_mint_prove_verify_round_trip() {
    // `note_owner` crosses the ABI as one field; the big-endian fold that
    // `emit::address_field` used to do in-circuit now happens here, and must
    // agree with `EthAddress::from_field` on the other side.
    let owner = address([0x22; 20]);
    let spend_key = Fr::from(17u64);
    let chain_id = 31_337u64;
    let note_amount = (1u128 << 80) + 100;
    let mint_units = (1u128 << 80) + 40;
    let serial = note_serial(owner, spend_key);
    let commitment = note_commitment(chain_id, serial, note_amount);
    let auth_path = single_leaf_path(chain_id);
    let root = common::root_from_path(EMIT, commitment, 0, &auth_path);
    let spent_nullifier = nullifier(commitment, spend_key);
    let next_key = hash_tagged(EMIT, "CHANGE_KEY", &[spend_key, spent_nullifier]);
    let change_commitment = note_commitment(chain_id, note_serial(owner, next_key), 60);

    let public = PublicInputs {
        chain_id,
        root,
        nullifier: spent_nullifier,
        note_owner: owner,
        mint_units,
        change_commitment,
    };
    let witness = Witness {
        note_amount,
        note_spend_key: spend_key,
        leaf_index: 0,
        auth_path,
    };

    common::assert_round_trip::<EmitMint>(
        &witness,
        &public,
        &[(
            "a different mint amount",
            PublicInputs {
                mint_units: mint_units + 1,
                ..public.clone()
            },
        )],
    );
}

/// `note_owner` crosses the ABI as an `EthAddress` struct, so `from_field` --
/// and its range check -- never runs on it. `EthAddress::validate()` in `main`
/// is the only thing left holding the 160-bit bound.
///
/// Every other constraint here is satisfied (serial, commitment, root and
/// nullifier are all derived from the oversized owner), so `validate` is the
/// sole reason this must fail. Delete that call and this test goes green.
#[test]
fn oversized_owner_is_rejected() {
    let mut bytes = [0u8; 21];
    bytes[0] = 1; // exactly 2^160 — one bit too wide for an address
    let owner = Fr::from_be_bytes_mod_order(&bytes);

    let spend_key = Fr::from(17u64);
    let chain_id = 31_337u64;
    let serial = note_serial(owner, spend_key);
    let commitment = note_commitment(chain_id, serial, 100);
    let auth_path = single_leaf_path(chain_id);
    let root = common::root_from_path(EMIT, commitment, 0, &auth_path);

    let public = PublicInputs {
        chain_id,
        root,
        nullifier: nullifier(commitment, spend_key),
        note_owner: owner,
        mint_units: 100,
        change_commitment: Fr::from(0u64),
    };
    let witness = Witness {
        note_amount: 100,
        note_spend_key: spend_key,
        leaf_index: 0,
        auth_path,
    };

    common::assert_unprovable::<EmitMint>(
        &witness,
        &public,
        "an owner of 2^160 must fail EthAddress::validate in-circuit",
    );
}
