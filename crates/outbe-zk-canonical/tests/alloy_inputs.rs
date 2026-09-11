#![cfg(feature = "alloy")]

use alloy_primitives::{B256, U256};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use outbe_protocol::error::Error;
use outbe_protocol::{protocol::zk::Circuit, Codec, OutbeV1};
use outbe_zk_canonical::noir;

fn word(value: u64) -> B256 {
    B256::from(U256::from(value))
}

fn point(value: u64) -> noir::alloy::EmbeddedCurvePoint {
    noir::alloy::EmbeddedCurvePoint {
        x: word(value),
        y: word(value + 1),
    }
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
                    proof.extend_from_slice(&OutbeV1::field_to_be_bytes(field));
                }
                let proof_words: Vec<_> = (0..c::PROOF_WORDS).map(|i| vec![i as u8; 32]).collect();
                proof.extend(proof_words.iter().flatten());
                let decoded = c::decode_public_inputs(&proof).unwrap();
                let alloy: c::alloy::PublicInputs = decoded.clone().try_into().unwrap();
                let public: c::PublicInputs = alloy.try_into().unwrap();
                assert_eq!(public, decoded);
                assert_eq!(<c::$marker as Circuit<OutbeV1>>::public_inputs(&public), fields);
            }
        )+};
    }
    check!(
        ownership_proof => OwnershipProof, full_proof => FullProof,
        emit_mint => EmitMint, paynote => Paynote,
        flat_aggregation_n1 => FlatAggregationN1, flat_aggregation_n2 => FlatAggregationN2,
        flat_aggregation_n4 => FlatAggregationN4, flat_aggregation_n8 => FlatAggregationN8,
        flat_aggregation_n16 => FlatAggregationN16, flat_aggregation_n32 => FlatAggregationN32,
        flat_aggregation_n64 => FlatAggregationN64,
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

    let signature = std::array::from_fn(|i| i as u8);
    let witness: noir::ownership_proof::Witness = noir::ownership_proof::alloy::Witness {
        pk: point(1),
        signature,
        nonce: word(3),
    }
    .try_into()
    .unwrap();
    assert_eq!(
        (witness.pk.x, witness.pk.y, witness.nonce),
        (Fr::from(1), Fr::from(2), Fr::from(3))
    );
    assert_eq!(witness.signature, signature);

    let alloy: noir::ownership_proof::alloy::Witness = witness.try_into().unwrap();
    assert_eq!(
        (alloy.pk.x, alloy.pk.y, alloy.nonce),
        (word(1), word(2), word(3))
    );
    assert_eq!(alloy.signature, signature);

    let witness: noir::full_proof::Witness = noir::full_proof::alloy::Witness {
        pk: point(1),
        signature,
        nonce: word(3),
        merkle_path_siblings: std::array::from_fn(|i| word(i as u64)),
        merkle_path_indices: std::array::from_fn(|i| i % 2 == 0),
    }
    .try_into()
    .unwrap();
    assert_eq!(witness.signature, signature);
    assert_eq!(
        witness.merkle_path_siblings,
        std::array::from_fn(|i| Fr::from(i as u64))
    );
    assert_eq!(
        witness.merkle_path_indices,
        std::array::from_fn(|i| i % 2 == 0)
    );
    let alloy: noir::full_proof::alloy::Witness = witness.try_into().unwrap();
    assert_eq!(
        (alloy.pk.x, alloy.pk.y, alloy.nonce),
        (word(1), word(2), word(3))
    );
    assert_eq!(alloy.signature, signature);
    assert_eq!(
        alloy.merkle_path_siblings,
        std::array::from_fn(|i| word(i as u64))
    );
    assert_eq!(
        alloy.merkle_path_indices,
        std::array::from_fn(|i| i % 2 == 0)
    );

    macro_rules! check_tiers {
        ($($module:ident),+ $(,)?) => {$(
            {
                use noir::$module as c;
                let witness: c::Witness = c::alloy::Witness {
                    pk: std::array::from_fn(|i| point(i as u64)),
                    nonce: std::array::from_fn(|i| word(i as u64 + 100)),
                    signature: std::array::from_fn(|i| [i as u8; 64]),
                }.try_into().unwrap();
                for i in 0..witness.pk.len() {
                    assert_eq!((witness.pk[i].x, witness.pk[i].y), (Fr::from(i as u64), Fr::from(i as u64 + 1)));
                    assert_eq!(witness.nonce[i], Fr::from(i as u64 + 100));
                    assert_eq!(witness.signature[i], [i as u8; 64]);
                }
                let alloy: c::alloy::Witness = witness.try_into().unwrap();
                for i in 0..alloy.pk.len() {
                    assert_eq!((alloy.pk[i].x, alloy.pk[i].y), (word(i as u64), word(i as u64 + 1)));
                    assert_eq!(alloy.nonce[i], word(i as u64 + 100));
                    assert_eq!(alloy.signature[i], [i as u8; 64]);
                }
            }
        )+};
    }
    check_tiers!(
        flat_aggregation_n1,
        flat_aggregation_n2,
        flat_aggregation_n4,
        flat_aggregation_n8,
        flat_aggregation_n16,
        flat_aggregation_n32,
        flat_aggregation_n64
    );
}

#[test]
fn conversions_reject_noncanonical_fields_including_nested_values() {
    let modulus = U256::from_be_slice(&Fr::MODULUS.to_bytes_be());
    for value in [modulus, modulus + U256::from(1), U256::MAX] {
        let public = noir::ownership_proof::alloy::PublicInputs {
            owner: B256::from(value),
            nft_hash: word(2),
            binding_hash: word(3),
        };
        assert!(noir::ownership_proof::PublicInputs::try_from(public).is_err());
    }
    let public: noir::ownership_proof::PublicInputs = noir::ownership_proof::alloy::PublicInputs {
        owner: B256::from(modulus - U256::from(1)),
        nft_hash: word(0),
        binding_hash: word(1),
    }
    .try_into()
    .unwrap();
    assert_eq!(public.owner, -Fr::from(1));

    let mut public = noir::flat_aggregation_n64::alloy::PublicInputs {
        public_inputs: [word(1); 129],
    };
    public.public_inputs[128] = B256::from(modulus);
    assert!(noir::flat_aggregation_n64::PublicInputs::try_from(public).is_err());

    let mut witness = noir::flat_aggregation_n64::alloy::Witness {
        pk: [point(1); 64],
        signature: [[0; 64]; 64],
        nonce: [word(3); 64],
    };
    witness.pk[63].y = B256::from(modulus);
    assert!(noir::flat_aggregation_n64::Witness::try_from(witness).is_err());

    let mut witness = noir::paynote::alloy::Witness {
        note_amount: U256::MAX,
        note_spend_key: word(1),
        leaf_index: 0,
        auth_path: [word(2); 32],
    };
    witness.auth_path[31] = B256::from(modulus);
    assert!(noir::paynote::Witness::try_from(witness).is_err());
}
