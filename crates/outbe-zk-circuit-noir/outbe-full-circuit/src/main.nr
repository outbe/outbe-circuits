// Full Proof Circuit.
//
// Composes the same sec.4.2 ownership constraint as `outbe-ownership-circuit`
// with a Merkle-inclusion check. There is intentionally one ownership
// implementation across the codebase --
// `outbe_circuit_core::ownership::verify_ownership_per_su` -- so the
// Grumpkin Schnorr semantics, the Poseidon3 owner derivation, and the
// `Poseidon2(nft_hash, nonce)` signature payload are identical whether
// the proof is standalone (`outbe-ownership-circuit`) or composed with
// inclusion here.

use outbe_circuit_core::inclusion;
use outbe_circuit_core::ownership;
use std::embedded_curve_ops::EmbeddedCurvePoint;

pub fn main(
    // Private witness.
    pk: EmbeddedCurvePoint,
    signature: [u8; 64],
    nonce: Field,
    merkle_path_siblings: [Field; 8],
    merkle_path_indices: [u8; 8],
    // Public -- same `(owner, nft_hash)` prefix as the standalone
    // ownership circuit, plus the Merkle root the inclusion check
    // resolves to.
    owner: pub Field,
    nft_hash: pub Field,
    expected_merkle_root: pub Field,
) {
    // Part 1: sec.4.2 ownership proof -- owner commitment + Grumpkin
    // Schnorr over Poseidon2(nft_hash, nonce). Same code path the
    // standalone ownership circuit uses.
    ownership::verify_ownership_per_su(pk, signature, nonce, owner, nft_hash);

    // Part 2: Merkle inclusion against the same `nft_hash`.
    let computed_merkle_root = inclusion::compute_merkle_root(
        nft_hash,
        merkle_path_siblings,
        merkle_path_indices,
    );
    assert(
        computed_merkle_root == expected_merkle_root,
        "merkle_root mismatch: inclusion proof failed",
    );
}

// ============================================
// Tests
// ============================================

#[test]
fn test_merkle_inclusion() {
    let leaf: Field = 0;
    let siblings: [Field; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let indices: [u8; 8] = [0, 1, 0, 1, 0, 1, 0, 1];

    let expected_merkle_tree_root = [
        104, 057, 009, 238, 038, 094, 110, 105, 035, 161, 094, 225, 051, 038, 244, 246, 031, 175,
        154, 035, 222, 125, 171, 102, 037, 145, 234, 128, 202, 151, 032, 009,
    ];

    let root = inclusion::compute_merkle_root(leaf, siblings, indices);
    let generated_root: [u8; 32] = root.to_le_bytes();
    assert_eq(expected_merkle_tree_root, generated_root);
}
