// Paynote private ERC20 payment-note circuit.
//
// Proves the right to spend `spend_amount` of a public `asset` out of a private
// note committed under the public `root`, publishing a nullifier and -- for a
// partial spend -- the commitment of the change note. The note is a bearer
// instrument: spend authority is knowledge of `note_spend_key`. There is no
// owner, no allow-list, and no action tag; the pool contract validates and
// routes the payment.
//
// The circuit checks that:
//   1. `asset` and `spender` are in-range addresses and nonzero.
//   2. `0 < spend_amount <= note_amount`, and the nullifier and spend key are
//      nonzero.
//   3. `note_spend_key` derives the note serial.
//   4. `(chain_id, serial, asset, note_amount)` derives a nonzero commitment
//      included under the public `root` via the depth-20 `leaf_index` and
//      `auth_path`. The asset and the amount live in the commitment -- not the
//      serial -- so the pool contract can build a deposit leaf from the transfer
//      it actually performed, and membership then attests both.
//   5. `(commitment, note_spend_key)` derives the public `nullifier`.
//   6. A partial spend publishes exactly the commitment for the remaining value,
//      using a spend key rotated by the current nullifier and inheriting the
//      SAME asset; a full spend publishes the zero change sentinel.
//
// The verifier/runtime remains responsible for binding `chain_id`, accepting
// `root`, rejecting an already-spent nullifier, inserting `change_commitment`
// (and skipping insertion when it is zero), deduplicating deposits on the leaf,
// and -- critically -- paying out to the public `spender`. A contract that pays
// `msg.sender` instead is trivially front-runnable: the proof is transferable,
// only its public inputs are bound.

mod paynote;
mod tests;

// `nullifier` is deliberately NOT imported: the public parameter of the same
// name would shadow it. It is called path-qualified as `paynote::nullifier`.
use outbe_circuit_core::types::EthAddress;
use paynote::{change_key, merkle_root, note_commitment, note_sn};

global MERKLE_DEPTH: u32 = 20;

fn main(
    chain_id: pub u64,
    root: pub Field,
    nullifier: pub Field,
    asset: pub EthAddress,
    spender: pub EthAddress,
    spend_amount: pub u64,
    change_commitment: pub Field,
    note_amount: u64,
    note_spend_key: Field,
    leaf_index: u32,
    auth_path: [Field; MERKLE_DEPTH],
) {
    // Both cross the ABI as `EthAddress` structs, so `from_field` -- and its
    // range check -- never runs on them. These calls are the only thing holding
    // the 160-bit bound; drop one and the bound silently disappears.
    asset.validate();
    spender.validate();

    assert(spend_amount > 0);
    assert(spend_amount <= note_amount);
    assert(nullifier != 0);
    assert(note_spend_key != 0);
    assert(asset.to_field() != 0);
    // `validate` permits zero, so this is a separate check -- and it is also
    // what keeps `spender` referenced beyond its range constraint.
    assert(spender.to_field() != 0);

    let serial = note_sn(note_spend_key);
    let commitment = note_commitment(chain_id, serial, asset, note_amount);
    let computed_root = merkle_root(commitment, leaf_index, auth_path);
    let computed_nullifier = paynote::nullifier(commitment, note_spend_key);

    assert(serial != 0);
    // Load-bearing: blocks spending a zero-padded empty tree slot.
    assert(commitment != 0);
    assert_eq(computed_root, root);
    assert_eq(computed_nullifier, nullifier);

    let remaining = note_amount - spend_amount;
    let creates_change = remaining > 0;
    assert((change_commitment != 0) == creates_change);
    if creates_change {
        let next_key = change_key(note_spend_key, computed_nullifier);
        let next_serial = note_sn(next_key);
        // The change note inherits the SAME asset, so it stays spendable in the
        // same token.
        let next_commitment = note_commitment(chain_id, next_serial, asset, remaining);
        let next_nullifier = paynote::nullifier(next_commitment, next_key);
        assert(next_key != 0);
        assert(next_serial != 0);
        assert(next_commitment != 0);
        assert_eq(change_commitment, next_commitment);
        assert(next_nullifier != 0);
    }
}
