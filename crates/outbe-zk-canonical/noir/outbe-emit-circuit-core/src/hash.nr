pub global POSEIDON2_TWO_INPUT_IV: Field = (2u128 << 64) as Field;

pub fn h2(left: Field, right: Field) -> Field {
    std::hash::poseidon2_permutation([left, right, 0 as Field, POSEIDON2_TWO_INPUT_IV])[0]
}

pub fn p<let N: u32>(tag: Field, values: [Field; N]) -> Field {
    let mut state = h2(EMIT_DOMAIN, tag);
    state = h2(state, N as Field);
    for i in 0..N {
        state = h2(state, values[i]);
    }
    state
}

// Big-endian ASCII protocol domain and purpose tags.
pub global EMIT_DOMAIN: Field = 0x4f555442455f454d4954; // "OUTBE_EMIT"
pub global TAG_POOL: Field = 0x454d49545f504f4f4c; // "EMIT_POOL"
pub global TAG_NOTE_SN: Field = 0x454d49545f4e4f54455f534e; // "EMIT_NOTE_SN"
pub global TAG_COMMITMENT: Field = 0x454d49545f434f4d4d49544d454e54; // "EMIT_COMMITMENT"
pub global TAG_NULLIFIER: Field = 0x454d49545f4e554c4c4946494552; // "EMIT_NULLIFIER"
pub global TAG_CHANGE_KEY: Field = 0x454d49545f4348414e47455f4b4559; // "EMIT_CHANGE_KEY"
pub global TAG_EMPTY: Field = 0x454d49545f454d505459; // "EMIT_EMPTY"
pub global TAG_NODE: Field = 0x454d49545f4e4f4445; // "EMIT_NODE"

pub fn pool_id(chain_id: u64, instance_id: Field) -> Field {
    p(TAG_POOL, [chain_id as Field, instance_id])
}

pub fn address_field(address: [u8; 20]) -> Field {
    let mut result = 0;
    for i in 0..20 {
        result = result * 256 + address[i] as Field;
    }
    result
}

pub fn note_sn(note_owner: [u8; 20], note_spend_key: Field) -> Field {
    p(TAG_NOTE_SN, [address_field(note_owner), note_spend_key])
}

pub fn note_commitment(pool: Field, serial: Field, note_amount: u64) -> Field {
    p(TAG_COMMITMENT, [pool, serial, note_amount as Field])
}

pub fn nullifier(pool: Field, serial: Field, note_spend_key: Field) -> Field {
    p(TAG_NULLIFIER, [pool, serial, note_spend_key])
}

pub fn change_key(note_spend_key: Field, note_nullifier: Field) -> Field {
    p(TAG_CHANGE_KEY, [note_spend_key, note_nullifier])
}
