//! Real barretenberg prove→verify round-trip for the canonical Paynote circuit.
//!
//! The formulas are reimplemented off-circuit here on purpose: the point of the
//! test is that Rust-computed public inputs match the in-circuit ones, which
//! only means something if the two derivations are independent.

use ark_ff::PrimeField;

use outbe_protocol::primitive::hash::FieldHasher;
use outbe_protocol::protocol::zk::{ProofGenerator, ProofVerifier};
use outbe_protocol::{OutbeV1, Suite};
use outbe_zk_backend::barretenberg::Barretenberg;
use outbe_zk_canonical::noir::paynote::{Paynote, PublicInputs, Witness};

type Fr = <OutbeV1 as Suite>::Field;

fn h2(left: Fr, right: Fr) -> Fr {
    <<OutbeV1 as Suite>::Hash as FieldHasher<Fr>>::hash(&[left, right]).unwrap()
}

fn h3(first: Fr, second: Fr, third: Fr) -> Fr {
    <<OutbeV1 as Suite>::Hash as FieldHasher<Fr>>::hash(&[first, second, third]).unwrap()
}

fn ascii_field(value: &str) -> Fr {
    Fr::from_be_bytes_mod_order(value.as_bytes())
}

fn hash_multi(tag: Fr, values: &[Fr]) -> Fr {
    let mut state = h2(tag, Fr::from(values.len() as u64));
    for value in values {
        state = h2(state, *value);
    }
    state
}

/// Mirror of `outbe_circuit_core::tags::tag` under Paynote's domain: a base
/// purpose tag folded with the domain that owns it.
fn paynote_tag(base: &str) -> Fr {
    h2(ascii_field("OUTBE_PAYNOTE"), ascii_field(base))
}

/// One 20-byte address = one big-endian field element. Must agree with
/// `EthAddress::from_field` on the circuit side.
fn address(bytes: [u8; 20]) -> Fr {
    Fr::from_be_bytes_mod_order(&bytes)
}

fn note_serial(spend_key: Fr) -> Fr {
    hash_multi(paynote_tag("NOTE_SN"), &[spend_key])
}

fn note_commitment(chain_id: u64, serial: Fr, asset: Fr, amount: u128) -> Fr {
    hash_multi(
        paynote_tag("COMMITMENT"),
        &[Fr::from(chain_id), serial, asset, Fr::from(amount)],
    )
}

/// Derived from the commitment, not the serial — so every leaf has exactly one
/// nullifier, and `chain_id` needs no separate input.
fn nullifier(commitment: Fr, spend_key: Fr) -> Fr {
    hash_multi(paynote_tag("NULLIFIER"), &[commitment, spend_key])
}

fn single_leaf_path(chain_id: u64) -> [Fr; 32] {
    let mut path = [Fr::from(0u64); 32];
    let domain = ascii_field("OUTBE_PAYNOTE");
    path[0] = hash_multi(paynote_tag("EMPTY"), &[Fr::from(chain_id)]);
    for level in 1..32 {
        path[level] = h3(domain, path[level - 1], path[level - 1]);
    }
    path
}

fn root_from_path(leaf: Fr, leaf_index: u32, path: &[Fr; 32]) -> Fr {
    let mut current = leaf;
    let domain = ascii_field("OUTBE_PAYNOTE");
    for (level, sibling) in path.iter().copied().enumerate() {
        let is_left = (leaf_index >> level) & 1 == 0;
        current = if is_left {
            h3(domain, current, sibling)
        } else {
            h3(domain, sibling, current)
        };
    }
    current
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
    let root = root_from_path(commitment, 0, &auth_path);
    let spent_nullifier = nullifier(commitment, spend_key);

    // The change note inherits the same asset, so it stays spendable in the
    // same token.
    let next_key = hash_multi(paynote_tag("CHANGE_KEY"), &[spend_key, spent_nullifier]);
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

    let backend = Barretenberg::default();
    let proof = ProofGenerator::<OutbeV1, Paynote>::generate(&backend, &witness, &public)
        .expect("Paynote proof generation");
    assert!(
        ProofVerifier::<OutbeV1, Paynote>::verify(&backend, &public, &proof).unwrap(),
        "valid partial-spend proof must verify"
    );

    let mut wrong_amount = public.clone();
    wrong_amount.spend_amount += 1;
    assert!(
        !ProofVerifier::<OutbeV1, Paynote>::verify(&backend, &wrong_amount, &proof).unwrap(),
        "proof must not verify for a different spend amount"
    );

    let mut wrong_asset = public.clone();
    wrong_asset.asset = address([0x22; 20]);
    assert!(
        !ProofVerifier::<OutbeV1, Paynote>::verify(&backend, &wrong_asset, &proof).unwrap(),
        "proof must not verify for a different asset"
    );

    // Binding `spender` is what stops a mempool observer lifting the proof and
    // redirecting the payment.
    let mut wrong_spender = public.clone();
    wrong_spender.spender = address([0x44; 20]);
    assert!(
        !ProofVerifier::<OutbeV1, Paynote>::verify(&backend, &wrong_spender, &proof).unwrap(),
        "proof must not verify for a different spender"
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
    let root = root_from_path(commitment, 0, &auth_path);

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

    let backend = Barretenberg::default();
    assert!(
        ProofGenerator::<OutbeV1, Paynote>::generate(&backend, &witness, &public).is_err(),
        "an asset of 2^160 must fail EthAddress::validate in-circuit"
    );
}
