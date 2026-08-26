// Emit private-note mint circuit.
//
// Proves knowledge of `(note_amount, note_spend_key, leaf_index, auth_path)` for
// a note bound to the public `(chain_id, note_owner)` without revealing the note
// amount or spend key.
//
// The circuit checks that:
//   1. `0 < mint_units <= note_amount`, and the spend key and nullifier are
//      nonzero.
//   2. `note_owner` and `note_spend_key` derive the note serial.
//   3. `(chain_id, serial, note_amount)` derives a nonzero commitment included
//      under the public `root` via the depth-20 `leaf_index` and `auth_path`.
//   4. `(chain_id, serial, note_spend_key)` derives the public `nullifier`.
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

use emit::{change_key, merkle_root, note_commitment, note_sn};
use outbe_circuit_core::types::EthAddress;

global MERKLE_DEPTH: u32 = 20;

fn main(
    chain_id: pub u64,
    root: pub Field,
    nullifier: pub Field,
    note_owner: pub EthAddress,
    mint_units: pub u64,
    change_commitment: pub Field,
    note_amount: u64,
    note_spend_key: Field,
    leaf_index: u32,
    auth_path: [Field; MERKLE_DEPTH],
) {
    assert(mint_units > 0);
    assert(mint_units <= note_amount);
    assert(nullifier != 0);
    assert(note_spend_key != 0);
    note_owner.validate();

    let serial = note_sn(note_owner, note_spend_key);
    let commitment = note_commitment(chain_id, serial, note_amount);
    let computed_root = merkle_root(commitment, leaf_index, auth_path);
    let computed_nullifier = emit::nullifier(chain_id, serial, note_spend_key);

    assert(serial != 0);
    assert(commitment != 0);
    assert_eq(computed_root, root);
    assert_eq(computed_nullifier, nullifier);

    let remaining = note_amount - mint_units;
    let creates_change = remaining > 0;
    assert((change_commitment != 0) == creates_change);
    if creates_change {
        let next_key = change_key(note_spend_key, computed_nullifier);
        let next_serial = note_sn(note_owner, next_key);
        let next_commitment = note_commitment(chain_id, next_serial, remaining);
        let next_nullifier = emit::nullifier(chain_id, next_serial, next_key);
        assert(next_key != 0);
        assert(next_serial != 0);
        assert(next_commitment != 0);
        assert_eq(change_commitment, next_commitment);
        assert(next_nullifier != 0);
    }
}
