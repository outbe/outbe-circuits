// Emit private-note mint circuit.
//
// Proves knowledge of `(note_amount, note_spend_key, leaf_index, auth_path)` for
// a note bound to the public `(chain_id, note_owner)` without revealing the note
// amount or spend key. Amounts are 256-bit (`bignum::U256`, three 120-bit
// little-endian limbs).
//
// The circuit checks that:
//   1. `0 < mint_units <= note_amount` over the integers, and the spend key and
//      nullifier are nonzero.
//   2. `note_owner` and `note_spend_key` derive the note serial.
//   3. `(chain_id, serial, note_amount)` derives a nonzero commitment included
//      under the public `root` via the depth-32 `leaf_index` and `auth_path`.
//   4. The note commitment and spend key derive the public `nullifier`.
//   5. A partial mint publishes exactly the commitment for the remaining value,
//      using a spend key rotated by the current nullifier; a full mint publishes
//      the zero change sentinel.
//
// The verifier/runtime remains responsible for binding `chain_id`, accepting
// `root`, rejecting an already-spent nullifier, recording any change commitment,
// and authorizing/routing the payout. The payout recipient and ledger state
// transition are not circuit inputs.

mod emit;
mod tests;

use bignum::{BigNum, U256};
use emit::{change_key, merkle_root, note_commitment, note_sn};
use outbe_circuit_core::merkle_tree::DEPTH;
use outbe_circuit_core::types::EthAddress;

fn main(
    chain_id: pub u64,
    root: pub Field,
    nullifier: pub Field,
    note_owner: pub EthAddress,
    mint_units: pub U256,
    change_commitment: pub Field,
    note_amount: U256,
    note_spend_key: Field,
    leaf_index: u32,
    auth_path: [Field; DEPTH],
) {
    // The ABI crosses amounts as three raw `u128` limbs with no range check,
    // and bignum v0.10.0's `from_limbs` does not constrain them either, but
    // every `U256` limb-wise operation below (ordering, subtraction, the
    // commitment limb preimage) assumes canonical limbs: < 2^120 each, top
    // limb < 2^17. `validate_in_range` is the canonicality gate, exactly
    // like `EthAddress::validate` for the owner.
    mint_units.validate_in_range();
    note_amount.validate_in_range();

    // Canonical limbs are non-negative and below the field modulus, so a
    // limb-sum of zero identifies exactly the zero amount.
    mint_units.assert_is_not_zero_integer();
    assert(mint_units <= note_amount);
    assert(nullifier != 0);
    assert(note_spend_key != 0);
    note_owner.validate();

    let serial = note_sn(note_owner, note_spend_key);
    let commitment = note_commitment(chain_id, serial, note_amount);
    let computed_root = merkle_root(commitment, leaf_index, auth_path);
    let computed_nullifier = emit::nullifier(commitment, note_spend_key);

    assert(serial != 0);
    assert(commitment != 0);
    assert_eq(computed_root, root);
    assert_eq(computed_nullifier, nullifier);

    // Exact integer subtraction: the `<=` above is what rules out the
    // mod-2^256 wrap `U256` subtraction would otherwise apply silently.
    let remaining = note_amount - mint_units;
    let creates_change = !remaining.is_zero_integer();
    assert((change_commitment != 0) == creates_change);
    if creates_change {
        let next_key = change_key(note_spend_key, computed_nullifier);
        let next_serial = note_sn(note_owner, next_key);
        let next_commitment = note_commitment(chain_id, next_serial, remaining);
        let next_nullifier = emit::nullifier(next_commitment, next_key);
        assert(next_key != 0);
        assert(next_serial != 0);
        assert(next_commitment != 0);
        assert_eq(change_commitment, next_commitment);
        assert(next_nullifier != 0);
    }
}
