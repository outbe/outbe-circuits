// Merkle tree inclusion proof module

use crate::hash;

/// Compute a Merkle root with `tag` prepended to every inner-node hash.
/// `path_siblings` and `path_indices` are little-endian; `true` places the
/// current node on the left and `false` places it on the right.
pub fn compute_merkle_root<let DEPTH: u32>(
    tag: Field,
    leaf: Field,
    path_siblings: [Field; DEPTH],
    path_indices: [bool; DEPTH],
) -> Field {
    let mut current_hash = leaf;

    for i in 0..DEPTH {
        let sibling = path_siblings[i];
        let is_left = path_indices[i];

        let (left, right) = if is_left {
            (current_hash, sibling)
        } else {
            (sibling, current_hash)
        };

        current_hash = hash::hash_3([tag, left, right])
    }

    current_hash
}
