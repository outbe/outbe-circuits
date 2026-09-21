#![allow(clippy::doc_lazy_continuation)]
//! The ZK-canonical half of the protocol battery. Exercises the
//! build-generated noir circuit types (`EmitMint` / `Paynote` and their
//! `Witness` / `PublicInputs`) through the core ZK seams.

use ark_ff::PrimeField;
use outbe_zk_canonical::CircuitId;
use outbe_zk_core::zk::Circuit;
use outbe_zk_core::Error;
use outbe_zk_core::Fr;

#[test]
fn generated_combined_proof_codecs() {
    use outbe_zk_canonical::noir;
    use outbe_zk_core::codec::field_to_be_bytes;

    macro_rules! check {
        ($($module:ident => $marker:ident),+ $(,)?) => {$(
            {
                use noir::$module as c;
                let fields: Vec<_> = (1..=c::PUBLIC_INPUT_COUNT).map(|i| Fr::from(i as u64)).collect();
                let mut combined = (fields.len() as u32).to_be_bytes().to_vec();
                for field in &fields {
                    combined.extend_from_slice(&field_to_be_bytes(field));
                }
                let proof: Vec<_> = (0..c::PROOF_WORDS).map(|i| vec![i as u8; 32]).collect();
                combined.extend(proof.iter().flatten());
                let public = c::decode_public_inputs(&combined).unwrap();
                assert_eq!(<c::$marker as Circuit>::public_inputs(&public), fields);
                assert_eq!(c::encode_combined_proof(public.clone(), proof.clone()).unwrap(), combined);
                for count in [0, c::PROOF_WORDS - 1, c::PROOF_WORDS + 1] {
                    assert!(matches!(
                        c::encode_combined_proof(public.clone(), vec![vec![0; 32]; count]),
                        Err(Error::Proof(_))
                    ));
                }
                for len in [0, 31, 33] {
                    let mut malformed = proof.clone();
                    malformed[c::PROOF_WORDS - 1].resize(len, 0);
                    assert!(matches!(c::encode_combined_proof(public.clone(), malformed), Err(Error::Proof(_))));
                }
                for malformed in [&combined[..3], &combined[..4], &combined[..combined.len() - 1]] {
                    assert!(matches!(c::decode_public_inputs(malformed), Err(Error::Proof(_))));
                }
                let mut wrong_count = combined.clone();
                wrong_count[..4].copy_from_slice(&0u32.to_be_bytes());
                assert!(matches!(c::decode_public_inputs(&wrong_count), Err(Error::Proof(_))));
                combined[4..36].fill(0xff);
                assert!(matches!(c::decode_public_inputs(&combined), Err(Error::NonCanonical("public input"))));
            }
        )+};
    }
    check!(
        emit_mint => EmitMint, paynote => Paynote,
    );
}

#[test]
fn generated_combined_proof_lengths_match_frozen_layouts() {
    use outbe_zk_canonical::{emit_mint, paynote};

    // Released wire sizes: Paynote and Emit both have log_n=14.
    assert_eq!(
        (
            paynote::PUBLIC_INPUT_COUNT,
            paynote::PROOF_WORDS,
            paynote::COMBINED_LEN
        ),
        (9, 250, 8292)
    );
    assert_eq!(
        (
            emit_mint::PUBLIC_INPUT_COUNT,
            emit_mint::PROOF_WORDS,
            emit_mint::COMBINED_LEN
        ),
        (8, 250, 8260)
    );
}

/// The Emit mint statement carries 8 public field elements: `chain_id`, two
/// field scalars, the owner address as one `EthAddress`-packed field, the
/// three 120-bit `U256` limbs of `mint_units`, and the change commitment.
#[test]
fn emit_mint_descriptor_and_abi_layout() {
    use outbe_zk_canonical::noir::emit_mint as emit;

    assert_eq!(emit::EmitMint::LABEL, "outbe.emit.mint");
    assert_eq!(emit::EmitMint::VERSION, "1.5.0");
    assert!(!emit::EmitMint::BYTECODE_B64.is_empty());
    assert_ne!(emit::EmitMint::CIRCUIT_HASH, [0u8; 32]);
    assert!(!emit::EmitMint::VK_BYTES.is_empty());
    assert_ne!(emit::EmitMint::VK_HASH, [0u8; 32]);

    // Above the old u128 ceiling, so the upper limbs must carry value.
    let public_limbs = [(1u128 << 100) + 40, 0xf << 8, 0];
    let private_limbs = [(1u128 << 100) + 100, 0xf << 8, 0];
    let public = emit::PublicInputs {
        chain_id: 1,
        root: Fr::from(2u64),
        nullifier: Fr::from(3u64),
        note_owner: Fr::from_be_bytes_mod_order(&[0x22; 20]),
        mint_units: public_limbs,
        change_commitment: Fr::from(4u64),
    };
    let flat = <emit::EmitMint as Circuit>::public_inputs(&public);
    assert_eq!(flat.len(), 8, "Emit mint public-input arity");
    assert_eq!(
        &flat[..3],
        &[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]
    );
    assert_eq!(
        flat[3],
        Fr::from_be_bytes_mod_order(&[0x22; 20]),
        "note_owner is one big-endian-packed field, not 20 byte leaves"
    );
    assert_eq!(
        &flat[4..7],
        public_limbs.map(Fr::from).as_slice(),
        "u256 mint_units follows note_owner as three little-endian 120-bit limbs"
    );
    assert_eq!(flat[7], Fr::from(4u64), "change_commitment is last");

    let witness = emit::Witness {
        note_amount: private_limbs,
        note_spend_key: Fr::from(5u64),
        leaf_index: 1,
        auth_path: [Fr::from(7u64); 32],
    };
    let all = <emit::EmitMint as Circuit>::witness_inputs(&witness, &public);
    assert_eq!(all.len(), 45, "8 public + 37 private ABI leaves");
    assert_eq!(
        &all[..8],
        flat.as_slice(),
        "public inputs are the ABI prefix"
    );
    assert_eq!(
        &all[8..11],
        private_limbs.map(Fr::from).as_slice(),
        "u256 note_amount is encoded as three limbs without truncation"
    );
    assert_eq!(all[11], Fr::from(5u64), "note_spend_key");
    assert_eq!(all[12], Fr::from(1u64), "leaf_index");
    assert_eq!(&all[13..], &[Fr::from(7u64); 32], "auth_path");

    assert!(
        outbe_zk_canonical::noir::CIRCUIT_REGISTRY
            .iter()
            .any(|e| e.label == "outbe.emit.mint"),
        "Emit mint missing from CIRCUIT_REGISTRY"
    );
    assert!(
        outbe_zk_canonical::noir::CIRCUIT_REGISTRY
            .iter()
            .all(|e| e.label != "outbe.commitment_nullifier"),
        "revoked commitment-nullifier must not remain in CIRCUIT_REGISTRY"
    );
}

/// Paynote's descriptor and ABI layout. Mirrors the Emit mint case: the two
/// addresses cross as `EthAddress` newtypes, so each is a single packed field
/// rather than 20 byte leaves.
#[test]
fn paynote_descriptor_and_abi_layout() {
    use outbe_zk_canonical::noir::paynote as pay;

    assert_eq!(pay::Paynote::LABEL, "outbe.paynote");
    assert_eq!(pay::Paynote::VERSION, "1.2.0");
    assert!(!pay::Paynote::BYTECODE_B64.is_empty());
    assert_ne!(pay::Paynote::CIRCUIT_HASH, [0u8; 32]);
    assert!(!pay::Paynote::VK_BYTES.is_empty());
    assert_ne!(pay::Paynote::VK_HASH, [0u8; 32]);

    let asset = Fr::from_be_bytes_mod_order(&[0xa0; 20]);
    let owner = Fr::from_be_bytes_mod_order(&[0x33; 20]);
    let spend_amount = [(1u128 << 100) + 40, 0xf << 8, 0];
    let note_amount = [(1u128 << 100) + 100, 0xf << 8, 0];
    let public = pay::PublicInputs {
        chain_id: 1,
        root: Fr::from(2u64),
        nullifier: Fr::from(3u64),
        asset,
        owner,
        spend_amount,
        change_commitment: Fr::from(4u64),
    };
    let flat = <pay::Paynote as Circuit>::public_inputs(&public);
    assert_eq!(flat.len(), 9, "Paynote public-input arity");
    assert_eq!(
        &flat[..3],
        &[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]
    );
    assert_eq!(
        flat[3], asset,
        "asset is one big-endian-packed field, not 20 byte leaves"
    );
    assert_eq!(flat[4], owner, "owner likewise");
    assert_eq!(
        &flat[5..8],
        spend_amount.map(Fr::from).as_slice(),
        "u256 spend_amount follows owner as three little-endian 120-bit limbs"
    );
    assert_eq!(flat[8], Fr::from(4u64), "change_commitment is last");

    let witness = pay::Witness {
        note_amount,
        note_spend_key: Fr::from(5u64),
        leaf_index: 1,
        auth_path: [Fr::from(7u64); 32],
    };
    let all = <pay::Paynote as Circuit>::witness_inputs(&witness, &public);
    assert_eq!(all.len(), 46, "9 public + 37 private ABI leaves");
    assert_eq!(
        &all[..9],
        flat.as_slice(),
        "public inputs are the ABI prefix"
    );
    assert_eq!(
        &all[9..12],
        note_amount.map(Fr::from).as_slice(),
        "u256 note_amount is encoded as three limbs without truncation"
    );
    assert_eq!(all[12], Fr::from(5u64), "note_spend_key");
    assert_eq!(all[13], Fr::from(1u64), "leaf_index");
    assert_eq!(&all[14..], &[Fr::from(7u64); 32], "auth_path");

    assert!(
        outbe_zk_canonical::noir::CIRCUIT_REGISTRY
            .iter()
            .any(|e| e.label == "outbe.paynote"),
        "Paynote missing from CIRCUIT_REGISTRY"
    );
}
