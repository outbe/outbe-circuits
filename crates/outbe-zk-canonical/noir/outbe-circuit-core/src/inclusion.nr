// Merkle tree inclusion proof module

use crate::hash2;

/// Compute Merkle root from leaf and path
/// path_siblings: Array of sibling hashes at each level (as Field elements)
/// path_indices: Array of position indicators (1 = current is left, 0 = current is right)
pub fn compute_merkle_root<let DEPTH: u32>(
    leaf: Field,
    path_siblings: [Field; DEPTH],
    path_indices: [u8; DEPTH],
) -> Field {
    let mut current_hash = leaf;

    for i in 0..DEPTH {
        let sibling = path_siblings[i];
        let is_left = path_indices[i];

        // Range-check the direction bit. Without this any value other
        // than 1 falls into the `else` branch and is treated as 0, so
        // 255 distinct encodings collapse to "right" -- a malleable
        // path. Constrain it to a genuine boolean.
        assert((is_left == 0) | (is_left == 1), "path index must be 0 or 1");

        // If is_left == 1, current is on left, sibling on right
        // If is_left == 0, sibling is on left, current on right
        let (left, right) = if is_left == 1 {
            (current_hash, sibling)
        } else {
            (sibling, current_hash)
        };

        current_hash = hash2::hash_2([left, right])
    }

    current_hash
}
