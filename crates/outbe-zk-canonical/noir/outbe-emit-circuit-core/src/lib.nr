pub mod hash;
pub mod merkle;

pub use hash::{address_field, change_key, h2, note_commitment, note_sn, nullifier, p, pool_id};
pub use merkle::{empty_leaf, merkle_root, node};

#[test]
fn address_is_big_endian() {
    assert_eq(address_field([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 1);
}

#[test]
fn key_rotation_changes_equal_value_notes() {
    let pool = pool_id(31337, 19);
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(pool, serial, 100);
    let n = nullifier(pool, serial, key);
    let next_key = change_key(key, n);
    let next_serial = note_sn(owner, next_key);
    let next_commitment = note_commitment(pool, next_serial, 100);
    let next_n = nullifier(pool, next_serial, next_key);

    assert(serial != next_serial);
    assert(commitment != next_commitment);
    assert(n != next_n);
}

#[test]
fn one_owner_key_pair_has_one_nullifier() {
    let pool = pool_id(31337, 19);
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment_a = note_commitment(pool, serial, 40);
    let commitment_b = note_commitment(pool, serial, 60);

    assert(commitment_a != commitment_b);
    assert_eq(nullifier(pool, serial, key), nullifier(pool, serial, key));
}

#[test]
fn formulas_match_rust_golden_vector() {
    let pool = pool_id(31337, 19);
    let owner = [0x22; 20];
    let key = 17;
    let serial = note_sn(owner, key);
    let commitment = note_commitment(pool, serial, 100);
    let n = nullifier(pool, serial, key);
    let next_key = change_key(key, n);
    let next_serial = note_sn(owner, next_key);
    let change = note_commitment(pool, next_serial, 60);
    let next_n = nullifier(pool, next_serial, next_key);

    assert_eq(pool, 969213159910377433811964485868132459794303973887568689588122047148167498530);
    assert_eq(address_field(owner), 194866884977453722427157977695504402620791005730);
    assert_eq(
        serial,
        21342069310807916791070165700294080153113769986217756573438676288943608782167,
    );
    assert_eq(
        commitment,
        8920638757974090424485532263260121962525033826692412398410028031560850059997,
    );
    assert_eq(n, 19930841266603247048080830523758161913321076552323859460402573568308199418853);
    assert_eq(
        next_key,
        21461890074168482987110003954155567720576581706363182096168600738873718329938,
    );
    assert_eq(
        next_serial,
        4804287315815397593652624173604400056762776097902001494732435778080491199566,
    );
    assert_eq(change, 5468794441128790897128673636740044755071741348299012657807004533299518097477);
    assert_eq(
        next_n,
        14850479296701909084487305492658561037291654050483941227387606902003089266194,
    );

    let mut path = [0; 20];
    path[0] = empty_leaf(pool);
    for level in 1..20 {
        path[level] = node(level - 1, path[level - 1], path[level - 1]);
    }
    assert_eq(
        merkle_root(commitment, 0, path),
        15863624322506346888338673496989700917235781017342367708880786949076752059001,
    );
}
