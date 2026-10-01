use bignum::{BigNum, U256};
use outbe_circuit_core::{hash::hash_multi, merkle_tree, tags::tag};
use outbe_circuit_core::types::EthAddress;

pub global PLEDGE_DOMAIN: Field = 0x4f555442455f504c45444745;

pub fn owner_serial(owner: EthAddress, secret: Field) -> Field {
    hash_multi(
        tag(PLEDGE_DOMAIN, 0x6f776e65722d73657269616c),
        [owner.to_field(), secret],
    )
}
pub fn note_commitment(chain_id: u64, serial: Field, amount: U256, receipt: Field) -> Field {
    let limbs = amount.get_limbs();
    hash_multi(
        tag(PLEDGE_DOMAIN, 0x706c656467652d6e6f7465),
        [
            chain_id as Field,
            serial,
            limbs[0] as Field,
            limbs[1] as Field,
            limbs[2] as Field,
            receipt,
        ],
    )
}
pub fn note_nullifier(commitment: Field, secret: Field) -> Field {
    hash_multi(
        tag(PLEDGE_DOMAIN, 0x706c656467652d6e756c6c6966696572),
        [commitment, secret],
    )
}
pub fn change_key(secret: Field, nullifier: Field) -> Field {
    hash_multi(
        tag(PLEDGE_DOMAIN, 0x6368616e67652d6b6579),
        [secret, nullifier],
    )
}
pub fn return_key(secret: Field, nullifier: Field, context: Field) -> Field {
    hash_multi(
        tag(PLEDGE_DOMAIN, 0x72657475726e2d6b6579),
        [secret, nullifier, context],
    )
}
pub fn receipt_context(position: U256, released_total: U256) -> Field {
    let p = position.get_limbs();
    let a = released_total.get_limbs();
    hash_multi(
        tag(PLEDGE_DOMAIN, 0x72657475726e2d72656365697074),
        [p[0] as Field, p[1] as Field, p[2] as Field, a[0] as Field, a[1] as Field, a[2] as Field],
    )
}
pub fn empty_leaf(chain_id: u64) -> Field {
    hash_multi(tag(PLEDGE_DOMAIN, 0x656d707479), [chain_id as Field])
}
pub fn merkle_root(leaf: Field, index: u32, path: [Field; 32]) -> Field {
    merkle_tree::merkle_root(PLEDGE_DOMAIN, leaf, index as Field, path)
}

// Both profiles share exactly one commitment formula and one nullifier formula.
pub fn spend(
    chain_id: u64,
    root: Field,
    nullifier: Field,
    context: Field,
    amount: U256,
    change: Field,
    owner: EthAddress,
    secret: Field,
    note_amount: U256,
    receipt: Field,
    index: u32,
    path: [Field; 32],
) {
    owner.validate();
    assert(owner.to_field() != 0);
    assert(secret != 0);
    assert(context != 0);
    amount.validate_in_field();
    note_amount.validate_in_field();
    amount.assert_is_not_zero();
    note_amount.assert_is_not_zero();
    assert(amount <= note_amount);
    let serial = owner_serial(owner, secret);
    let commitment = note_commitment(chain_id, serial, note_amount, receipt);
    assert(serial != 0);
    assert(commitment != 0);
    assert(nullifier != 0);
    assert_eq(note_nullifier(commitment, secret), nullifier);
    assert_eq(merkle_root(commitment, index, path), root);
    let remaining = note_amount - amount;
    let partial = !remaining.is_zero_integer();
    assert((change != 0) == partial);
    if partial {
        let key = change_key(secret, nullifier);
        let next_serial = owner_serial(owner, key);
        assert(key != 0);
        assert(next_serial != 0);
        assert_eq(change, note_commitment(chain_id, next_serial, remaining, 0));
        assert(note_nullifier(change, key) != 0);
    }
}

#[test]
fn ownership_receipts_and_contexts() {
    let owner = EthAddress::from_field(7);
    let serial = owner_serial(owner, 17);
    assert(serial != owner_serial(EthAddress::from_field(8), 17));
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
