#![cfg(feature = "alloy")]

use alloy_primitives::{B256, U256};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use outbe_zk_canonical::noir;
use outbe_zk_core::codec::field_to_be_bytes;
use outbe_zk_core::zk::Circuit;
use outbe_zk_core::Error;

fn word(value: u64) -> B256 {
    B256::from(U256::from(value))
}

#[test]
fn alloy_public_inputs_convert_back_to_circuit_abi() {
    macro_rules! check {
        ($($module:ident => $marker:ident),+ $(,)?) => {$(
            {
                use noir::$module as c;
                let fields: Vec<_> = (1..=c::PUBLIC_INPUT_COUNT).map(|i| Fr::from(i as u64)).collect();
                let mut proof = (fields.len() as u32).to_be_bytes().to_vec();
                for field in &fields {
                    proof.extend_from_slice(&field_to_be_bytes(field));
                }
                let proof_words: Vec<_> = (0..c::PROOF_WORDS).map(|i| vec![i as u8; 32]).collect();
                proof.extend(proof_words.iter().flatten());
                let decoded = c::decode_public_inputs(&proof).unwrap();
                let alloy: c::alloy::PublicInputs = decoded.clone().try_into().unwrap();
                let public: c::PublicInputs = alloy.try_into().unwrap();
                assert_eq!(public, decoded);
                assert_eq!(<c::$marker as Circuit>::public_inputs(&public), fields);
            }
        )+};
    }
    check!(
        emit_mint => EmitMint, paynote => Paynote,
    );
}

#[test]
fn circuit_public_inputs_convert_to_alloy_with_checked_ranges() {
    use outbe_zk_canonical::paynote;
    let public = paynote::PublicInputs {
        chain_id: u64::MAX,
        root: -Fr::from(1),
        nullifier: Fr::from(2),
        asset: Fr::from_be_bytes_mod_order(&[0xff; 20]),
        owner: Fr::from_be_bytes_mod_order(&[0x22; 20]),
        spend_amount: [(1u128 << 120) - 1, (1u128 << 120) - 1, 65535],
        change_commitment: Fr::from(3),
    };
    let alloy: paynote::alloy::PublicInputs = public.clone().try_into().unwrap();
    assert_eq!(alloy.chain_id, u64::MAX);
    assert_eq!(
        alloy.root,
        B256::from(U256::from_be_slice(&Fr::MODULUS.to_bytes_be()) - U256::from(1))
    );
    assert_eq!(alloy.asset, alloy_primitives::Address::from([0xff; 20]));
    assert_eq!(alloy.owner, alloy_primitives::Address::from([0x22; 20]));
    assert_eq!(alloy.spend_amount, U256::MAX);
    assert_eq!(paynote::PublicInputs::try_from(alloy).unwrap(), public);

    for field in ["asset", "owner"] {
        let mut invalid = public.clone();
        let oversized = Fr::from_be_bytes_mod_order(&[1; 21]);
        if field == "asset" {
            invalid.asset = oversized;
        } else {
            invalid.owner = oversized;
        }
        assert!(matches!(
            paynote::alloy::PublicInputs::try_from(invalid),
            Err(Error::NonCanonical("address"))
        ));
    }
    for (index, bits) in [(0, 120), (1, 120), (2, 16)] {
        let mut invalid = public.clone();
        invalid.spend_amount[index] = 1u128 << bits;
        assert!(matches!(
            paynote::alloy::PublicInputs::try_from(invalid),
            Err(Error::NonCanonical("uint256 limbs"))
        ));
    }
}

#[test]
fn alloy_witnesses_preserve_amounts_points_and_nested_arrays() {
    macro_rules! check_note {
        ($module:ident) => {{
            use noir::$module as c;
            let witness: c::Witness = c::alloy::Witness {
                note_amount: U256::MAX,
                note_spend_key: word(7),
                leaf_index: u32::MAX,
                auth_path: std::array::from_fn(|i| word(i as u64)),
            }
            .try_into()
            .unwrap();
            assert_eq!(
                witness.note_amount,
                [(1u128 << 120) - 1, (1u128 << 120) - 1, 65535]
            );
            assert_eq!(witness.note_spend_key, Fr::from(7));
            assert_eq!(witness.leaf_index, u32::MAX);
            assert_eq!(
                witness.auth_path,
                std::array::from_fn(|i| Fr::from(i as u64))
            );
            let alloy: c::alloy::Witness = witness.clone().try_into().unwrap();
            assert_eq!(alloy.note_amount, U256::MAX);
            assert_eq!(alloy.note_spend_key, word(7));
            assert_eq!(alloy.leaf_index, u32::MAX);
            assert_eq!(alloy.auth_path, std::array::from_fn(|i| word(i as u64)));
            for (index, bits) in [(0, 120), (1, 120), (2, 16)] {
                let mut invalid = witness.clone();
                invalid.note_amount[index] = 1u128 << bits;
                assert!(matches!(
                    c::alloy::Witness::try_from(invalid),
                    Err(Error::NonCanonical("uint256 limbs"))
                ));
            }
        }};
    }
    check_note!(paynote);
    check_note!(emit_mint);
}

#[test]
fn conversions_reject_noncanonical_fields_including_nested_values() {
    let modulus = U256::from_be_slice(&Fr::MODULUS.to_bytes_be());

    // A non-canonical word nested inside an array must be rejected too.
    let mut witness = noir::paynote::alloy::Witness {
        note_amount: U256::MAX,
        note_spend_key: word(1),
        leaf_index: 0,
        auth_path: [word(2); 32],
    };
    witness.auth_path[31] = B256::from(modulus);
    assert!(noir::paynote::Witness::try_from(witness).is_err());
}
