//! Real baratenberg prove→verify round-trip for the canonical Emit mint circuit.

mod common;

use ark_ff::PrimeField;

use outbe_zk_canonical::noir::emit_mint::{EmitMint, PublicInputs, Witness};
use outbe_zk_canonical::u256;

use common::{address, hash_tagged, AuthPath, Fr};

const EMIT: &str = "OUTBE_EMIT";

fn note_serial(owner: Fr, spend_key: Fr) -> Fr {
    hash_tagged(EMIT, "NOTE_SN", &[owner, spend_key])
}

/// Mirror of `emit::note_commitment`: the preimage is
/// `(chain_id, serial, amount_limbs)` — the 256-bit amount enters as its three
/// canonical little-endian radix-2^120 limbs, never folded into one field
/// element (which would alias amounts differing by the field modulus).
fn note_commitment(chain_id: u64, serial: Fr, amount: [u128; 3]) -> Fr {
    hash_tagged(
        EMIT,
        "COMMITMENT",
        &[
            Fr::from(chain_id),
            serial,
            Fr::from(amount[0]),
            Fr::from(amount[1]),
            Fr::from(amount[2]),
        ],
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
    // Above the old u128 ceiling: the upper limbs carry real value through
    // the commitment preimage and the change arithmetic.
    let note_amount = (0xabu128, (1u128 << 100) + 100);
    let mint_units = (0xabu128, (1u128 << 100) + 40);
    let note_amount = u256::to_limbs(note_amount.0, note_amount.1);
    let mint_units = u256::to_limbs(mint_units.0, mint_units.1);
    let serial = note_serial(owner, spend_key);
    let commitment = note_commitment(chain_id, serial, note_amount);
    let auth_path = single_leaf_path(chain_id);
    let root = common::root_from_path(EMIT, commitment, 0, &auth_path);
    let spent_nullifier = nullifier(commitment, spend_key);
    let next_key = hash_tagged(EMIT, "CHANGE_KEY", &[spend_key, spent_nullifier]);
    let change_commitment = note_commitment(
        chain_id,
        note_serial(owner, next_key),
        u256::to_limbs(0, 60),
    );

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
                mint_units: u256::to_limbs(0xab, (1u128 << 100) + 41),
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
    let commitment = note_commitment(chain_id, serial, u256::to_limbs(0, 100));
    let auth_path = single_leaf_path(chain_id);
    let root = common::root_from_path(EMIT, commitment, 0, &auth_path);

    let public = PublicInputs {
        chain_id,
        root,
        nullifier: nullifier(commitment, spend_key),
        note_owner: owner,
        mint_units: u256::to_limbs(0, 100),
        change_commitment: Fr::from(0u64),
    };
    let witness = Witness {
        note_amount: u256::to_limbs(0, 100),
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

/// `mint_units` crosses the ABI as raw `u128` limbs; nothing at the boundary
/// range-checks them. `U256::validate_in_range` inside `main` is the only
/// canonicality gate, so a limb set above 2^120 must be rejected in-circuit
/// even though every derived relation (commitment, root, nullifier) was
/// computed from the value it visually encodes (2^127).
#[test]
fn non_canonical_mint_limb_is_rejected() {
    let owner = address([0x22; 20]);
    let spend_key = Fr::from(17u64);
    let chain_id = 31_337u64;
    let serial = note_serial(owner, spend_key);
    let commitment = note_commitment(chain_id, serial, u256::to_limbs(0, 200));
    let auth_path = single_leaf_path(chain_id);
    let root = common::root_from_path(EMIT, commitment, 0, &auth_path);

    let public = PublicInputs {
        chain_id,
        root,
        nullifier: nullifier(commitment, spend_key),
        note_owner: owner,
        // Limb 0 is 2^127: above the 120-bit radix, still a legal `u128` ABI
        // value, and numerically above `note_amount`.
        mint_units: [1u128 << 127, 0, 0],
        change_commitment: Fr::from(0u64),
    };
    let witness = Witness {
        note_amount: u256::to_limbs(0, 200),
        note_spend_key: spend_key,
        leaf_index: 0,
        auth_path,
    };

    common::assert_unprovable::<EmitMint>(
        &witness,
        &public,
        "a non-canonical mint_units limb must fail U256::validate_in_range",
    );
}
