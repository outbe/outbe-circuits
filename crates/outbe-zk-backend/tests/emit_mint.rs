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

fn note_commitment(pool: Fr, serial: Fr, amount: u64) -> Fr {
    emit_hash("EMIT_COMMITMENT", &[pool, serial, Fr::from(amount)])
}

fn nullifier(pool: Fr, serial: Fr, spend_key: Fr) -> Fr {
    emit_hash("EMIT_NULLIFIER", &[pool, serial, spend_key])
}

fn merkle_node(level: usize, left: Fr, right: Fr) -> Fr {
    emit_hash("EMIT_NODE", &[Fr::from(level as u64), left, right])
}

fn single_leaf_path(pool: Fr) -> [Fr; 20] {
    let mut path = [Fr::from(0u64); 20];
    path[0] = emit_hash("EMIT_EMPTY", &[pool]);
    for level in 1..20 {
        path[level] = merkle_node(level - 1, path[level - 1], path[level - 1]);
    }
    path
}

fn root_from_path(leaf: Fr, mut index: u32, path: &[Fr; 20]) -> Fr {
    let mut current = leaf;
    for (level, sibling) in path.iter().copied().enumerate() {
        current = if index & 1 == 0 {
            merkle_node(level, current, sibling)
        } else {
            merkle_node(level, sibling, current)
        };
        index >>= 1;
    }
    current
}

#[test]
fn emit_partial_mint_prove_verify_round_trip() {
    let owner = [0x22; 20];
    let spend_key = Fr::from(17u64);
    let pool = emit_hash("EMIT_POOL", &[Fr::from(31_337u64), Fr::from(19u64)]);
    let serial = note_serial(owner, spend_key);
    let commitment = note_commitment(pool, serial, 100);
    let auth_path = single_leaf_path(pool);
    let root = root_from_path(commitment, 0, &auth_path);
    let spent_nullifier = nullifier(pool, serial, spend_key);
    let next_key = emit_hash("EMIT_CHANGE_KEY", &[spend_key, spent_nullifier]);
    let change_commitment = note_commitment(pool, note_serial(owner, next_key), 60);

    let public = PublicInputs {
        pool_id: pool,
        root,
        nullifier: spent_nullifier,
        note_owner: owner,
        mint_units: 40,
        change_commitment,
    };
    let witness = Witness {
        note_amount: 100,
        note_spend_key: spend_key,
        leaf_index: 0,
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
