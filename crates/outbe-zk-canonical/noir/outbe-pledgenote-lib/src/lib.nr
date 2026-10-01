use bignum::{BigNum, U256};
use outbe_circuit_core::{hash::{ascii_field, hash_multi}, merkle_tree::{self, DEPTH}};
use outbe_circuit_core::tags::{
    tag, TAG_CHANGE_KEY, TAG_COMMITMENT, TAG_EMPTY, TAG_NOTE_SN, TAG_NULLIFIER,
};
use outbe_circuit_core::types::EthAddress;

// Keep the original note and tree hash domain.
pub global PLEDGENOTE_DOMAIN: Field = ascii_field("OUTBE_PLEDGE");

pub global TAG_RETURN_KEY: Field = ascii_field("RETURN_KEY");
pub global TAG_RECEIPT_CONTEXT: Field = ascii_field("RETURN_RECEIPT");

pub fn note_sn(owner: EthAddress, note_spend_key: Field) -> Field {
    hash_multi(
        tag(PLEDGENOTE_DOMAIN, TAG_NOTE_SN),
        [owner.to_field(), note_spend_key],
    )
}
pub fn note_commitment(
    chain_id: u64,
    serial: Field,
    note_amount: U256,
    receipt_context: Field,
) -> Field {
    let limbs = note_amount.get_limbs();
    hash_multi(
        tag(PLEDGENOTE_DOMAIN, TAG_COMMITMENT),
        [
            chain_id as Field,
            serial,
            limbs[0] as Field,
            limbs[1] as Field,
            limbs[2] as Field,
            receipt_context,
        ],
    )
}
pub fn note_nullifier(commitment: Field, note_spend_key: Field) -> Field {
    hash_multi(
        tag(PLEDGENOTE_DOMAIN, TAG_NULLIFIER),
        [commitment, note_spend_key],
    )
}
pub fn change_key(note_spend_key: Field, spent_nullifier: Field) -> Field {
    hash_multi(
        tag(PLEDGENOTE_DOMAIN, TAG_CHANGE_KEY),
        [note_spend_key, spent_nullifier],
    )
}
pub fn return_key(note_spend_key: Field, nullifier: Field, context: Field) -> Field {
    hash_multi(
        tag(PLEDGENOTE_DOMAIN, TAG_RETURN_KEY),
        [note_spend_key, nullifier, context],
    )
}
pub fn receipt_context(position: U256, released_total: U256) -> Field {
    let p = position.get_limbs();
    let a = released_total.get_limbs();
    hash_multi(
        tag(PLEDGENOTE_DOMAIN, TAG_RECEIPT_CONTEXT),
        [p[0] as Field, p[1] as Field, p[2] as Field, a[0] as Field, a[1] as Field, a[2] as Field],
    )
}
pub fn empty_leaf(chain_id: u64) -> Field {
    hash_multi(tag(PLEDGENOTE_DOMAIN, TAG_EMPTY), [chain_id as Field])
}
pub fn merkle_root(leaf: Field, leaf_index: u32, auth_path: [Field; DEPTH]) -> Field {
    merkle_tree::merkle_root(PLEDGENOTE_DOMAIN, leaf, leaf_index as Field, auth_path)
}

// Both profiles share exactly one commitment formula and one nullifier formula.
pub fn spend(
    chain_id: u64,
    root: Field,
    nullifier: Field,
    context: Field,
    spend_amount: U256,
    change_commitment: Field,
    owner: EthAddress,
    note_spend_key: Field,
    note_amount: U256,
    receipt_context: Field,
    leaf_index: u32,
    auth_path: [Field; DEPTH],
) {
    owner.validate();
    assert(owner.to_field() != 0);
    assert(note_spend_key != 0);
    assert(context != 0);
    spend_amount.validate_in_field();
    note_amount.validate_in_field();
    spend_amount.assert_is_not_zero();
    note_amount.assert_is_not_zero();
    assert(spend_amount <= note_amount);
    let serial = note_sn(owner, note_spend_key);
    let commitment = note_commitment(chain_id, serial, note_amount, receipt_context);
    assert(serial != 0);
    assert(commitment != 0);
    assert(nullifier != 0);
    assert_eq(note_nullifier(commitment, note_spend_key), nullifier);
    assert_eq(merkle_root(commitment, leaf_index, auth_path), root);
    let remaining = note_amount - spend_amount;
    let creates_change = !remaining.is_zero_integer();
    assert((change_commitment != 0) == creates_change);
    if creates_change {
        let key = change_key(note_spend_key, nullifier);
        let next_serial = note_sn(owner, key);
        assert(key != 0);
        assert(next_serial != 0);
        assert_eq(change_commitment, note_commitment(chain_id, next_serial, remaining, 0));
        assert(note_nullifier(change_commitment, key) != 0);
    }
}

#[test]
fn ownership_receipts_and_contexts() {
    assert_eq(TAG_RETURN_KEY, 0x52455455524e5f4b4559);
    assert_eq(TAG_RECEIPT_CONTEXT, 0x52455455524e5f52454345495054);
    let owner = EthAddress::from_field(7);
    let serial = note_sn(owner, 17);
    assert(serial != note_sn(EthAddress::from_field(8), 17));
    let a = note_commitment(
        31337,
        serial,
        U256::from(40),
        receipt_context(U256::from(1), U256::from(40)),
    );
    let b = note_commitment(
        31337,
        serial,
        U256::from(40),
        receipt_context(U256::from(1), U256::from(80)),
    );
    assert(a != b);
    assert(note_nullifier(a, 17) != note_nullifier(b, 17));
    let nullifier = note_nullifier(a, 17);
    assert(return_key(17, nullifier, 1) != return_key(17, nullifier, 2));
}

#[test]
fn full_and_partial_spends() {
    let owner = EthAddress::from_field(7);
    let note_spend_key = 17;
    let note_amount = U256::from(100);
    let commitment = note_commitment(31337, note_sn(owner, note_spend_key), note_amount, 0);
    let nullifier = note_nullifier(commitment, note_spend_key);
    let auth_path = [0; DEPTH];
    let root = merkle_root(commitment, 0, auth_path);
    let next_key = change_key(note_spend_key, nullifier);
    let change_commitment = note_commitment(31337, note_sn(owner, next_key), U256::from(60), 0);
    spend(
        31337,
        root,
        nullifier,
        1,
        U256::from(40),
        change_commitment,
        owner,
        note_spend_key,
        note_amount,
        0,
        0,
        auth_path,
    );
    spend(
        31337,
        root,
        nullifier,
        1,
        note_amount,
        0,
        owner,
        note_spend_key,
        note_amount,
        0,
        0,
        auth_path,
    );
}

#[test(should_fail)]
fn spend_rejects_wrong_owner() {
    let note_amount = U256::from(100);
    let commitment = note_commitment(
        31337,
        note_sn(EthAddress::from_field(7), 17),
        note_amount,
        0,
    );
    let nullifier = note_nullifier(commitment, 17);
    let auth_path = [0; DEPTH];
    spend(
        31337,
        merkle_root(commitment, 0, auth_path),
        nullifier,
        1,
        note_amount,
        0,
        EthAddress::from_field(8),
        17,
        note_amount,
        0,
        0,
        auth_path,
    );
}
