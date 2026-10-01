use bignum::U256;
use outbe_circuit_core::{merkle_tree::DEPTH, types::EthAddress};
fn main(
    chain_id: pub u64,
    root: pub Field,
    nullifier: pub Field,
    context: pub Field,
    spend_amount: pub U256,
    change_commitment: pub Field,
    return_note_serial: pub Field,
    owner: EthAddress,
    note_spend_key: Field,
    note_amount: U256,
    receipt_context: Field,
    leaf_index: u32,
    auth_path: [Field; DEPTH],
) {
    pledgenote_lib::spend(
        chain_id,
        root,
        nullifier,
        context,
        spend_amount,
        change_commitment,
        owner,
        note_spend_key,
        note_amount,
        receipt_context,
        leaf_index,
        auth_path,
    );
    let key = pledgenote_lib::return_key(note_spend_key, nullifier, context);
    assert(key != 0);
    assert(return_note_serial != 0);
    assert_eq(return_note_serial, pledgenote_lib::note_sn(owner, key));
}
