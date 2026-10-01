use bignum::U256;
use outbe_circuit_core::types::EthAddress;
fn main(
    chain_id: pub u64,
    root: pub Field,
    nullifier: pub Field,
    context: pub Field,
    spend_amount: pub U256,
    change_commitment: pub Field,
    return_note_serial: pub Field,
    source: EthAddress,
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
        source,
        note_secret,
        note_amount,
        receipt_context,
        leaf_index,
        auth_path,
    );
    let key = pledge_lib::return_key(note_secret, nullifier, context);
    assert(key != 0);
    assert(return_note_serial != 0);
    assert_eq(return_note_serial, pledge_lib::owner_serial(source, key));
}
