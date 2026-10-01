use bignum::U256;
use outbe_circuit_core::{merkle_tree::DEPTH, types::EthAddress};
fn main(
    chain_id: pub u64,
    root: pub Field,
    nullifier: pub Field,
    context: pub Field,
    spend_amount: pub U256,
    change_commitment: pub Field,
    owner: pub EthAddress,
    note_spend_key: Field,
    note_amount: U256,
    receipt_context: Field,
    leaf_index: u32,
    auth_path: [Field; DEPTH],
) {
    pledge_lib::spend(
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
}
