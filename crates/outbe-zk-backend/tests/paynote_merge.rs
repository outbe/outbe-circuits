//! Real frozen merge proofs, public binding, and settlement interoperability.
use alloy_primitives::{Address, U256};
use ark_bn254::Fr;
use ark_ff::Field as _;
use outbe_protocol::protocol::zk::ProofGenerator;
use outbe_protocol::{codec, FieldElement};
use outbe_zk_backend::barretenberg::{verify_circuit, Barretenberg};
use outbe_zk_canonical::{
    noir::paynote::Paynote,
    paynote::{hash::*, Tree},
    paynote_merge::*,
};

fn fixture(count: usize, amounts: [U256; 4]) -> (Witness, PublicInputs, Tree, U256) {
    let asset = Address::repeat_byte(0x33);
    let mut tree = Tree::new(paynote_domain(), empty_leaf(31337).unwrap(), 32).unwrap();
    let mut witness = Witness {
        note_amounts: [[0; 3]; 4],
        note_spend_keys: [Fr::from(0); 4],
        leaf_indices: [0; 4],
        auth_paths: [[Fr::from(0); 32]; 4],
        output_spend_key: Fr::from(99),
    };
    let mut public = PublicInputs {
        chain_id: 31337,
        pool: Fr::from(0x1019),
        root: Fr::from(0),
        input_count: count.try_into().unwrap(),
        asset: asset.to_field().unwrap(),
        nullifiers: [Fr::from(0); 4],
        output_commitment: Fr::from(0),
    };
    let mut total = U256::ZERO;
    for (i, amount) in amounts.into_iter().enumerate().take(count) {
        let key = Fr::from(17 + i as u64);
        let commitment = note_commitment(31337, note_sn(key).unwrap(), asset, amount).unwrap();
        tree.append(commitment).unwrap();
        witness.note_spend_keys[i] = key;
        witness.note_amounts[i] = outbe_protocol::codec::u256_limbs_be(&amount.to_be_bytes());
        witness.leaf_indices[i] = i.try_into().unwrap();
        public.nullifiers[i] = note_nullifier(commitment, key).unwrap();
        total = total.checked_add(amount).unwrap();
    }
    for (i, auth_path) in witness.auth_paths.iter_mut().enumerate().take(count) {
        *auth_path = tree
            .inclusion_path(i as u64)
            .unwrap()
            .siblings
            .try_into()
            .unwrap();
    }
    public.root = tree.root();
    public.output_commitment = note_commitment(
        31337,
        note_sn(witness.output_spend_key).unwrap(),
        asset,
        total,
    )
    .unwrap();
    (witness, public, tree, total)
}

fn prove(w: &Witness, p: &PublicInputs) -> Vec<u8> {
    let proof = ProofGenerator::<PaynoteMerge>::generate(&Barretenberg::default(), w, p).unwrap();
    encode_combined_proof(p.clone(), proof.proof).unwrap()
}

#[test]
fn merged_note_uses_ordinary_settlement_and_binds_every_public_word() {
    let (w, p, mut tree, total) = fixture(3, [12, 8, 5, 0].map(U256::from));
    let combined = prove(&w, &p);
    assert_eq!(decode_public_inputs(&combined).unwrap(), p);
    assert_eq!(p.nullifiers.len(), MAX_MERGE_INPUTS);
    assert!(verify_circuit::<PaynoteMerge>(&combined).unwrap());
    assert!(!verify_circuit::<Paynote>(&combined).unwrap_or(false));
    for i in 0..PUBLIC_INPUT_COUNT {
        let mut altered = combined.clone();
        let start = 4 + i * 32;
        let word =
            codec::field_from_be32(&altered[start..start + 32].try_into().unwrap()) + Fr::from(1);
        altered[start..start + 32].copy_from_slice(&codec::field_to_be_bytes(&word));
        assert!(
            !verify_circuit::<PaynoteMerge>(&altered).unwrap_or(false),
            "public word {i}"
        );
    }
    assert_eq!(total, U256::from(25));
    let index = tree.append(p.output_commitment).unwrap().0;
    let nullifier = note_nullifier(p.output_commitment, w.output_spend_key).unwrap();
    let next_key = change_key(w.output_spend_key, nullifier).unwrap();
    let public = outbe_zk_canonical::noir::paynote::PublicInputs {
        chain_id: p.chain_id,
        root: tree.root(),
        nullifier,
        asset: p.asset,
        context: Fr::from(123),
        spend_amount: [20, 0, 0],
        change_commitment: note_commitment(
            p.chain_id,
            note_sn(next_key).unwrap(),
            Address::repeat_byte(0x33),
            U256::from(5),
        )
        .unwrap(),
    };
    let witness = outbe_zk_canonical::noir::paynote::Witness {
        note_amount: [25, 0, 0],
        note_spend_key: w.output_spend_key,
        leaf_index: index.try_into().unwrap(),
        auth_path: tree
            .inclusion_path(index)
            .unwrap()
            .siblings
            .try_into()
            .unwrap(),
    };
    let proof =
        ProofGenerator::<Paynote>::generate(&Barretenberg::default(), &witness, &public).unwrap();
    let spend = outbe_zk_canonical::paynote::encode_combined_proof(public, proof.proof).unwrap();
    assert!(verify_circuit::<Paynote>(&spend).unwrap());
    assert!(!verify_circuit::<PaynoteMerge>(&spend).unwrap_or(false));
}

#[test]
fn raw_abi_cannot_bypass_amount_address_and_padding_constraints() {
    let (w, p, _, _) = fixture(3, [12, 8, 5, 0].map(U256::from));
    let mut cases = Vec::new();
    let mut bad = w.clone();
    bad.note_amounts[0] = [0, 0, 1 << 16];
    cases.push((bad, p.clone()));
    bad = w.clone();
    bad.note_amounts[0] = [1 << 120, 0, 0];
    cases.push((bad, p.clone()));
    bad = w.clone();
    bad.note_amounts[3] = [1, 0, 0];
    cases.push((bad, p.clone()));
    bad = w.clone();
    bad.note_spend_keys[3] = Fr::from(1);
    cases.push((bad, p.clone()));
    bad = w.clone();
    bad.leaf_indices[3] = 1;
    cases.push((bad, p.clone()));
    bad = w.clone();
    bad.auth_paths[3][31] = Fr::from(1);
    cases.push((bad, p.clone()));
    let mut wrong = p;
    wrong.asset = Fr::from(2).pow([160]);
    cases.push((w, wrong));
    for (witness, public) in cases {
        assert!(ProofGenerator::<PaynoteMerge>::generate(
            &Barretenberg::default(),
            &witness,
            &public
        )
        .is_err());
    }
}

#[test]
#[allow(clippy::print_stderr)] // Reports benchmark timings under --nocapture.
fn four_input_profile_benchmark_and_u256_boundary() {
    let (w, p, _, total) = fixture(
        4,
        [U256::MAX - U256::from(3), U256::ONE, U256::ONE, U256::ONE],
    );
    assert_eq!(total, U256::MAX);
    let start = std::time::Instant::now();
    let proof = prove(&w, &p);
    let prove_time = start.elapsed();
    let start = std::time::Instant::now();
    for _ in 0..10 {
        assert!(verify_circuit::<PaynoteMerge>(&proof).unwrap());
    }
    eprintln!("paynote_merge: public_words={PUBLIC_INPUT_COUNT}, proof_bytes={}, prove_ms={}, verify_mean_us={}",
        proof.len(), prove_time.as_millis(), start.elapsed().as_micros()/10);
}

#[test]
fn decoder_rejects_malformed_and_noncanonical_words() {
    let (_, p, _, _) = fixture(2, [12, 8, 0, 0].map(U256::from));
    let valid = encode_combined_proof(p, vec![vec![0; 32]; PROOF_WORDS]).unwrap();
    for length in [0, 3, valid.len() - 1, valid.len() + 1] {
        let mut bytes = valid.clone();
        bytes.resize(length, 0);
        assert!(decode_public_inputs(&bytes).is_err());
    }
    for (i, bits) in [(0, 64), (1, 160), (3, 32), (4, 160)] {
        let mut bytes = valid.clone();
        let word = Fr::from(2).pow([bits]);
        bytes[4 + i * 32..4 + (i + 1) * 32].copy_from_slice(&codec::field_to_be_bytes(&word));
        assert!(decode_public_inputs(&bytes).is_err());
    }
    let mut bytes = valid;
    bytes[4 + 5 * 32..4 + 6 * 32].fill(255);
    assert!(decode_public_inputs(&bytes).is_err());
}
