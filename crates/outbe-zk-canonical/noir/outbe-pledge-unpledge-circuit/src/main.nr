use bignum::U256;
use outbe_circuit_core::types::EthAddress;
fn main(
    chain_id: pub u64,
    root: pub Field,
    nullifier: pub Field,
    context: pub Field,
    spend_amount: pub U256,
    change_commitment: pub Field,
    destination: pub EthAddress,
    note_secret: Field,
    note_amount: U256,
    receipt_context: Field,
    leaf_index: u32,
    auth_path: [Field; 32],
) {
    pledge_lib::spend(
        chain_id,
        root,
        nullifier,
        context,
        spend_amount,
        change_commitment,
        destination,
        note_secret,
        note_amount,
        receipt_context,
        leaf_index,
        auth_path,
    );
}
