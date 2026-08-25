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

fn note_serial(owner: [u8; 20], spend_key: Fr) -> Fr {
    emit_hash(
        "EMIT_NOTE_SN",
        &[Fr::from_be_bytes_mod_order(&owner), spend_key],
    )
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
    let owner = [0x22; 20];
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
