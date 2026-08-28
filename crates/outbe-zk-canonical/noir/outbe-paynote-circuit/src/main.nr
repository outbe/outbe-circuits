// Paynote private ERC20 payment-note circuit.
//
// Proves the right to spend `spend_amount` of a public `asset` out of a private
// note committed under the public `root`, publishing a nullifier and -- for a
// partial spend -- the commitment of the change note. The note is a bearer
// instrument: spend authority is knowledge of `note_spend_key`.

mod paynote;
mod tests;

// `nullifier` is deliberately NOT imported: the public parameter of the same
// name would shadow it. It is called path-qualified as `paynote::nullifier`.
use outbe_circuit_core::merkle_tree::DEPTH;
use outbe_circuit_core::types::EthAddress;
use paynote::{change_key, merkle_root, note_commitment, note_sn, note_nullifier};

// TODO consider implementing ownership verification?

fn main(
    chain_id: pub u64,
    root: pub Field,
    nullifier: pub Field,
    asset: pub EthAddress,
    spender: pub EthAddress,
    spend_amount: pub u128,
    change_commitment: pub Field,
    note_amount: u128,
    note_spend_key: Field,
    leaf_index: u32,
    auth_path: [Field; DEPTH],
) {
    assert(spend_amount > 0);
    assert(spend_amount <= note_amount);
    assert(nullifier != 0);
    assert(note_spend_key != 0);
    asset.validate();
    spender.validate();
    assert(spender.to_field() != 0);

    let serial = note_sn(note_spend_key);
    let commitment = note_commitment(chain_id, serial, asset, note_amount);
    let computed_root = merkle_root(commitment, leaf_index, auth_path);
    let computed_nullifier = note_nullifier(commitment, note_spend_key);

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
        let next_nullifier = note_nullifier(next_commitment, next_key);
        assert(next_key != 0);
        assert(next_serial != 0);
        assert(next_commitment != 0);
        assert_eq(change_commitment, next_commitment);
        assert(next_nullifier != 0);
    }
}
