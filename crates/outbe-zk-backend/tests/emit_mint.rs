//! Real barretenberg prove→verify round-trip for the canonical Emit mint circuit.

use ark_ff::PrimeField;

use outbe_protocol::primitive::hash::FieldHasher;
use outbe_protocol::protocol::zk::{ProofGenerator, ProofVerifier};
use outbe_protocol::{OutbeV1, Suite};
use outbe_zk_backend::barretenberg::Barretenberg;
use outbe_zk_canonical::noir::emit_mint::{EmitMint, PublicInputs, Witness};

type Fr = <OutbeV1 as Suite>::Field;

fn h2(left: Fr, right: Fr) -> Fr {
    <<OutbeV1 as Suite>::Hash as FieldHasher<Fr>>::hash(&[left, right]).unwrap()
}

fn ascii_field(value: &str) -> Fr {
    Fr::from_be_bytes_mod_order(value.as_bytes())
}

fn emit_hash(tag: &str, values: &[Fr]) -> Fr {
    let mut state = h2(ascii_field("OUTBE_EMIT"), ascii_field(tag));
    state = h2(state, Fr::from(values.len() as u64));
    for value in values {
        state = h2(state, *value);
    }
    state
}

fn note_serial(owner: Fr, spend_key: Fr) -> Fr {
    emit_hash("EMIT_NOTE_SN", &[owner, spend_key])
}

fn note_commitment(chain_id: u64, serial: Fr, amount: u64) -> Fr {
    emit_hash(
        "EMIT_COMMITMENT",
        &[Fr::from(chain_id), serial, Fr::from(amount)],
    )
}

fn nullifier(chain_id: u64, serial: Fr, spend_key: Fr) -> Fr {
    emit_hash("EMIT_NULLIFIER", &[Fr::from(chain_id), serial, spend_key])
}

fn single_leaf_path(chain_id: u64) -> [Fr; 20] {
    let mut path = [Fr::from(0u64); 20];
    path[0] = emit_hash("EMIT_EMPTY", &[Fr::from(chain_id)]);
    for level in 1..20 {
        path[level] = h2(path[level - 1], path[level - 1]);
    }
    path
}

fn root_from_path(leaf: Fr, path_bits: &[bool; 20], path: &[Fr; 20]) -> Fr {
    let mut current = leaf;
    for (is_right, sibling) in path_bits.iter().copied().zip(path.iter().copied()) {
        current = if is_right {
            h2(sibling, current)
        } else {
            h2(current, sibling)
        };
    }
    current
}

#[test]
fn emit_partial_mint_prove_verify_round_trip() {
    // `note_owner` crosses the ABI as one field; the big-endian fold that
    // `emit::address_field` used to do in-circuit now happens here, and must
    // agree with `EthAddress::from_field` on the other side.
    let owner = Fr::from_be_bytes_mod_order(&[0x22u8; 20]);
    let spend_key = Fr::from(17u64);
    let chain_id = 31_337u64;
    let path_bits = [false; 20];
    let serial = note_serial(owner, spend_key);
    let commitment = note_commitment(chain_id, serial, 100);
    let auth_path = single_leaf_path(chain_id);
    let root = root_from_path(commitment, &path_bits, &auth_path);
    let spent_nullifier = nullifier(chain_id, serial, spend_key);
    let next_key = emit_hash("EMIT_CHANGE_KEY", &[spend_key, spent_nullifier]);
    let change_commitment = note_commitment(chain_id, note_serial(owner, next_key), 60);

    let public = PublicInputs {
        chain_id,
        root,
        nullifier: spent_nullifier,
        note_owner: owner,
        mint_units: 40,
        change_commitment,
    };
    let witness = Witness {
        note_amount: 100,
        note_spend_key: spend_key,
        path_bits,
        auth_path,
    };

    let backend = Barretenberg::default();
    let proof = ProofGenerator::<OutbeV1, EmitMint>::generate(&backend, &witness, &public)
        .expect("Emit mint proof generation");
    assert!(
        ProofVerifier::<OutbeV1, EmitMint>::verify(&backend, &public, &proof).unwrap(),
        "valid partial-mint proof must verify"
    );

    let mut wrong = public.clone();
    wrong.mint_units += 1;
    assert!(
        !ProofVerifier::<OutbeV1, EmitMint>::verify(&backend, &wrong, &proof).unwrap(),
        "proof must not verify for a different mint amount"
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
    let path_bits = [false; 20];
    let serial = note_serial(owner, spend_key);
    let commitment = note_commitment(chain_id, serial, 100);
    let auth_path = single_leaf_path(chain_id);
    let root = root_from_path(commitment, &path_bits, &auth_path);

    let public = PublicInputs {
        chain_id,
        root,
        nullifier: nullifier(chain_id, serial, spend_key),
        note_owner: owner,
        mint_units: 100,
        change_commitment: Fr::from(0u64),
    };
    let witness = Witness {
        note_amount: 100,
        note_spend_key: spend_key,
        path_bits,
        auth_path,
    };

    let backend = Barretenberg::default();
    assert!(
        ProofGenerator::<OutbeV1, EmitMint>::generate(&backend, &witness, &public).is_err(),
        "an owner of 2^160 must fail EthAddress::validate in-circuit"
    );
}
