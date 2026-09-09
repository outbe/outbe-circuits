//! Emit hash and Merkle formulas checked against a frozen circuit vector.

use alloy_primitives::{B256, U256};
use outbe_protocol::{Codec, OutbeV1};
use outbe_zk_canonical::{
    emit_mint::hash::{
        change_key, empty_subtrees, merkle_node, note_commitment, note_sn, nullifier, Field,
    },
    INCLUSION_DEPTH,
};

#[test]
fn formulas_match_pinned_circuit_vector() {
    let chain_id = 31_337u64;
    let owner = [0x22u8; 20];
    let key = Field::from(17u64);
    let serial = note_sn(owner, key).unwrap();
    let commitment = note_commitment(chain_id, serial, U256::from(100)).unwrap();
    let n = nullifier(commitment, key).unwrap();
    let next_key = change_key(key, n).unwrap();
    let next_serial = note_sn(owner, next_key).unwrap();
    let change = note_commitment(chain_id, next_serial, U256::from(60)).unwrap();
    let next_n = nullifier(change, next_key).unwrap();

    let zeros = empty_subtrees(chain_id, INCLUSION_DEPTH).unwrap();
    let mut root = merkle_node(commitment, zeros[0]).unwrap();
    for sibling in zeros.iter().take(INCLUSION_DEPTH).skip(1) {
        root = merkle_node(root, *sibling).unwrap();
    }

    let cases: [(Field, &str); 8] = [
        (
            serial,
            "0x0bb7a42dc8456b387d334b2b46ff1833eeda93134e947bcb9759363ebeb15f14",
        ),
        (
            commitment,
            "0x2908a2b4b3d801f4937fa62a77cfdb2c1653fc95f3ccdde6f2c25303241556a6",
        ),
        (
            n,
            "0x1c291f2dda40b80a655cfa18702cf9518993df0c27e864e2ad81809b1d395a33",
        ),
        (
            next_key,
            "0x1cfd27606ce2303a242c5ab395c981e3efad9658384972c98082ad08ae4d6df6",
        ),
        (
            next_serial,
            "0x2632987ca79080b3430ba9f04e4b14032473c0871494e9689a32da0679d94143",
        ),
        (
            change,
            "0x077056529800880c562feca3846bbb34831a16e781aeffce294ec183558efb64",
        ),
        (
            next_n,
            "0x197a0b51419905416c762add627f880dcce358fe120682112f1fca2c6a30f8b1",
        ),
        (
            root,
            "0x286ae1be8815c6c04b6b33e7aafefd79b28f5d5642128242129dfb8aab3fc3a6",
        ),
    ];
    for (actual, expected) in cases {
        assert_eq!(
            format!(
                "{:#x}",
                B256::from_slice(&OutbeV1::field_to_be_bytes(&actual))
            ),
            expected
        );
    }
}
