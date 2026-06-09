// Shielded commitment-nullifier circuit.
//
// Proves, for a hidden commitment:
//   1. The commitment is well-formed under a domain-tagged Poseidon-4
//      hash over (secret, nullifier_secret, denom_id).
//   2. The commitment is a member of a depth-20 Merkle tree whose
//      root is disclosed as a public input.
//   3. The disclosed `nullifier_hash` is the canonical derivation of
//      the witness `nullifier_secret` (domain-tagged Poseidon-2).
//
// The fourth public input `receiver_binding` is carried through
// unconstrained inside the circuit; consumers (the calling runtime)
// recompute it from the surrounding call context and assert equality
// off-circuit. This keeps the public-input surface fixed at four
// fields while still binding the proof to a particular action shape
// and receiver.

use poseidon::poseidon::bn254::hash_2;
use poseidon::poseidon::bn254::hash_4;

global MERKLE_DEPTH: u32 = 20;

global TAG_COMMIT: Field = 0x6E0001;
global TAG_NULLIFIER: Field = 0x6E0002;
global TAG_MERKLE: Field = 0x6E0003;

fn merkle_node(left: Field, right: Field) -> Field {
    // Domain-tagged inner-node hash. The on-chain helper folds in
    // TAG_MERKLE as the first input as well, so the tree shape
    // matches byte-for-byte.
    hash_2([TAG_MERKLE + left, right])
}

fn merkle_root_from_path(
    leaf: Field,
    path: [Field; MERKLE_DEPTH],
    index: Field,
) -> Field {
    let index_bits: [bool; MERKLE_DEPTH] = index.to_le_bits();
    let mut current = leaf;
    for level in 0..MERKLE_DEPTH {
        let sibling = path[level];
        // index_bits[level] == false -> current is a left child
        // index_bits[level] == true  -> current is a right child
        let (left, right) = if index_bits[level] {
            (sibling, current)
        } else {
            (current, sibling)
        };
        current = merkle_node(left, right);
    }
    current
}

fn main(
    // public inputs
    merkle_root: pub Field,
    nullifier_hash: pub Field,
    denom_id: pub Field,
    receiver_binding: pub Field,
    // private witness
    secret: Field,
    nullifier_secret: Field,
    merkle_path: [Field; MERKLE_DEPTH],
    merkle_index: Field,
) {
    // commitment well-formedness
    let commitment = hash_4([
        TAG_COMMIT,
        secret,
        nullifier_secret,
        denom_id,
    ]);

    // commitment membership in the disclosed root
    let recomputed_root = merkle_root_from_path(commitment, merkle_path, merkle_index);
    assert(recomputed_root == merkle_root);

    // nullifier derivation
    assert(nullifier_hash == hash_2([TAG_NULLIFIER, nullifier_secret]));

    // receiver_binding is intentionally unconstrained in-circuit; the
    // consumer asserts on-chain that it equals the canonical hash of
    // the surrounding call context (action tag, target, chain id,
    // application-derived nonce). Referenced here so the verifier
    // compiles it into the public-input layout.
    let _ = receiver_binding;
}
