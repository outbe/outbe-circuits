//! Incremental Merkle Tree (IMT) — suite-generic inclusion-tree logic.
//!
//! [`Imt`] is a binary, append-only Merkle tree whose node hash is
//! `S::Hash([domain, left, right])` (Poseidon2 for `OutbeV1`). It is generic
//! over the suite: only the field + hash are used, no curve/signature. The
//! caller supplies the domain, empty leaf, and depth. [`InclusionPath`] is
//! one membership proof (domain,
//! leaf index, and sibling hashes) that resolves a root and yields the
//! in-circuit direction bits.
//!
//! With `empty_leaf = 0`, this mirrors the on-chain commitment tree (`CommitmentWindowBase` in
//! outbe-chain-research): same shape, same domain-separated node hash, same
//! `empty_leaf = 0`, and the leaf stored at each position is the entity hash
//! directly. The depth and domain are caller parameters (the canonical
//! commitment tree fixes both).

use ark_ff::Zero;

use crate::error::Error;
use crate::primitive::hash::FieldHasher;
use crate::suite::Suite;

/// Result of a single frontier append — mirrors the on-chain `0x0204`
/// precompile output `(changedLevel, newSubtree, newRoot)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Append<F> {
    /// The single frontier level whose stored subtree changes.
    pub changed_level: usize,
    /// The new value to store at `frontier[changed_level]`.
    pub new_subtree: F,
    /// The tree root after the append operation.
    pub new_root: F,
}

/// A binary, append-only incremental Merkle tree over `S`'s field + hash
/// with a frontier for O(depth) appends and retained leaves for membership paths.
pub struct Imt<S: Suite> {
    domain: S::Field,
    depth: usize,
    /// Zero-subtree ladder, `depth + 1` entries.
    zeros: Vec<S::Field>,
    /// Filled left-subtree hash per level, `depth` entries.
    frontier: Vec<S::Field>,
    leaves: Vec<S::Field>,
    next_index: u64,
    root: S::Field,
}

impl<S: Suite> Imt<S> {
    fn validate_depth(depth: usize) -> Result<(), Error> {
        if !(1..=63).contains(&depth) {
            return Err(Error::Merkle(format!(
                "tree depth must be in 1..=63, got {depth}"
            )));
        }
        Ok(())
    }

    /// Parent node hash: `Hash([domain, left, right])`.
    pub fn node_hash(domain: S::Field, left: S::Field, right: S::Field) -> Result<S::Field, Error> {
        S::Hash::hash(&[domain, left, right])
    }

    /// Build the zero-subtree ladder: `zeros[0] = empty_leaf`,
    /// `zeros[i] = Hash([domain, zeros[i-1], zeros[i-1]])`. `zeros[level]` is
    /// the root of an all-empty subtree of height `level`. Has `depth + 1`
    /// entries.
    pub fn zero_ladder(
        domain: S::Field,
        empty_leaf: S::Field,
        depth: usize,
    ) -> Result<Vec<S::Field>, Error> {
        Self::validate_depth(depth)?;
        let mut zeros = Vec::with_capacity(depth + 1);
        zeros.push(empty_leaf);
        for level in 1..=depth {
            zeros.push(Self::node_hash(domain, zeros[level - 1], zeros[level - 1])?);
        }
        Ok(zeros)
    }

    /// Root of an empty depth-`depth` tree.
    pub fn empty_root(
        domain: S::Field,
        empty_leaf: S::Field,
        depth: usize,
    ) -> Result<S::Field, Error> {
        Ok(Self::zero_ladder(domain, empty_leaf, depth)?[depth])
    }

    /// Stateless frontier append (the `0x0204` precompile kernel): append `leaf`
    /// at `next_index` to the given `frontier` + `zeros` ladder, returning the
    /// single changed slot and the new root.
    pub fn frontier_append(
        domain: S::Field,
        frontier: &[S::Field],
        next_index: u64,
        leaf: S::Field,
        zeros: &[S::Field],
    ) -> Result<Append<S::Field>, Error> {
        let depth = frontier.len();
        Self::validate_depth(depth)?;
        if zeros.len() != depth + 1 {
            return Err(Error::Merkle(format!(
                "frontier_append: zeros.len() ({}) must be frontier.len()+1 ({})",
                zeros.len(),
                depth + 1
            )));
        }
        if next_index >= (1u64 << depth) {
            return Err(Error::Merkle(format!(
                "frontier_append: next_index {next_index} overflows depth-{depth} tree"
            )));
        }

        let mut current = leaf;
        let mut index = next_index;
        let mut changed: Option<(usize, S::Field)> = None;
        for level in 0..depth {
            if index & 1 == 0 {
                // Left child: the accumulated subtree becomes the new frontier
                // entry the first time we hit a zero bit; pair with the zeros.
                if changed.is_none() {
                    changed = Some((level, current));
                }
                current = Self::node_hash(domain, current, zeros[level])?;
            } else {
                // Right child: merge with the waiting left sibling.
                current = Self::node_hash(domain, frontier[level], current)?;
            }
            index >>= 1;
        }

        let (changed_level, new_subtree) = match changed {
            Some(c) => c,
            // Tree-completing append: no new left subtree waits; report the top
            // slot unchanged.
            None => (depth - 1, frontier[depth - 1]),
        };
        Ok(Append {
            changed_level,
            new_subtree,
            new_root: current,
        })
    }

    /// Recompute a root from an inclusion path: the `leaf`, its `leaf_index`,
    /// and the sibling hash at each level bottom-up. The index bits select
    /// left/right per level, so no per-element side flag is stored.
    pub fn root_from_inclusion_path(
        domain: S::Field,
        leaf: S::Field,
        leaf_index: u64,
        siblings: &[S::Field],
    ) -> Result<S::Field, Error> {
        let depth = siblings.len();
        Self::validate_depth(depth)?;
        if leaf_index >= (1u64 << depth) {
            return Err(Error::Merkle(format!(
                "root_from_inclusion_path: leaf_index {leaf_index} overflows depth-{depth} tree"
            )));
        }
        let mut current = leaf;
        let mut index = leaf_index;
        for sibling in siblings {
            current = if index & 1 == 0 {
                Self::node_hash(domain, current, *sibling)?
            } else {
                Self::node_hash(domain, *sibling, current)?
            };
            index >>= 1;
        }
        Ok(current)
    }

    /// A new tree with a caller-supplied empty leaf (for example, a chain-tagged
    /// PayNote or Emit empty leaf). Supports depths 1 through 63.
    pub fn new(domain: S::Field, empty_leaf: S::Field, depth: usize) -> Result<Self, Error> {
        let zeros = Self::zero_ladder(domain, empty_leaf, depth)?;
        let root = zeros[depth];
        Ok(Self {
            domain,
            depth,
            frontier: vec![S::Field::zero(); depth],
            leaves: Vec::new(),
            next_index: 0,
            zeros,
            root,
        })
    }

    /// Tree depth.
    pub fn depth(&self) -> usize {
        self.depth
    }
    /// Index the next appended leaf will occupy.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }
    /// Current tree root.
    pub fn root(&self) -> S::Field {
        self.root
    }

    /// Append `leaf` at the next index, updating the frontier + root. Returns
    /// the leaf's index and the frontier change.
    pub fn append(&mut self, leaf: S::Field) -> Result<(u64, Append<S::Field>), Error> {
        let index = self.next_index;
        let ins = Self::frontier_append(self.domain, &self.frontier, index, leaf, &self.zeros)?;
        self.leaves.push(leaf);
        self.frontier[ins.changed_level] = ins.new_subtree;
        self.root = ins.new_root;
        self.next_index += 1;
        Ok((index, ins))
    }

    /// Leaves in append order, retained in O(leaves + depth) storage.
    pub fn leaves(&self) -> &[S::Field] {
        &self.leaves
    }

    /// Root after exactly `leaf_count` appends, including the empty prefix.
    pub fn root_at(&self, leaf_count: usize) -> Result<S::Field, Error> {
        if leaf_count > self.leaves.len() {
            return Err(Error::Merkle("leaf count exceeds retained history".into()));
        }
        if leaf_count == self.leaves.len() {
            return Ok(self.root);
        }
        if leaf_count == 0 {
            return Ok(self.zeros[self.depth]);
        }
        let index = u64::try_from(leaf_count - 1)
            .map_err(|_| Error::Merkle("leaf index exceeds u64".into()))?;
        self.inclusion_path_at(index, leaf_count)?
            .root(self.leaves[leaf_count - 1])
    }

    /// Membership path for an appended leaf under the current root.
    pub fn inclusion_path(&self, leaf_index: u64) -> Result<InclusionPath<S>, Error> {
        self.inclusion_path_at(leaf_index, self.leaves.len())
    }

    /// Membership path under the root after exactly `leaf_count` appends.
    /// Rejects leaves that did not yet exist in that prefix.
    pub fn inclusion_path_at(
        &self,
        leaf_index: u64,
        leaf_count: usize,
    ) -> Result<InclusionPath<S>, Error> {
        let mut index = usize::try_from(leaf_index)
            .map_err(|_| Error::Merkle("leaf index exceeds usize".into()))?;
        if leaf_count > self.leaves.len() || index >= leaf_count {
            return Err(Error::Merkle(
                "leaf index or count outside retained history".into(),
            ));
        }
        // ponytail: O(leaves) work and temporary memory per path; cache levels if pool size warrants it.
        let mut nodes = self.leaves[..leaf_count].to_vec();
        let mut siblings = Vec::with_capacity(self.depth);
        for level in 0..self.depth {
            if nodes.len() % 2 == 1 {
                nodes.push(self.zeros[level]);
            }
            siblings.push(nodes[index ^ 1]);
            nodes = nodes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| Self::node_hash(self.domain, pair[0], pair[1]))
                .collect::<Result<Vec<_>, _>>()?;
            index >>= 1;
        }
        Ok(InclusionPath {
            domain: self.domain,
            leaf_index,
            siblings,
        })
    }

    /// The inclusion path for `leaf_index` in an otherwise-empty tree of this
    /// depth (every sibling is the empty-subtree root at its level) — the path
    /// for a freshly-inserted leaf before any sibling is filled.
    pub fn empty_inclusion_path(&self, leaf_index: u64) -> InclusionPath<S> {
        InclusionPath {
            domain: self.domain,
            leaf_index,
            siblings: self.zeros[..self.depth].to_vec(),
        }
    }
}

/// A Merkle inclusion (membership) proof: the leaf's index plus the sibling
/// hash at each level, bottom-up. `siblings.len()` is the tree depth.
pub struct InclusionPath<S: Suite> {
    /// Domain separator prepended to every inner-node hash.
    pub domain: S::Field,
    /// The leaf's position in the tree.
    pub leaf_index: u64,
    /// Sibling hashes, bottom-up.
    pub siblings: Vec<S::Field>,
}

// Manual `Clone` so the marker `S` need not be `Clone`.
impl<S: Suite> Clone for InclusionPath<S> {
    fn clone(&self) -> Self {
        Self {
            domain: self.domain,
            leaf_index: self.leaf_index,
            siblings: self.siblings.clone(),
        }
    }
}

impl<S: Suite> InclusionPath<S> {
    /// The tree depth this path covers.
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// Resolve the tree root this path commits `leaf` to.
    pub fn root(&self, leaf: S::Field) -> Result<S::Field, Error> {
        Imt::<S>::root_from_inclusion_path(self.domain, leaf, self.leaf_index, &self.siblings)
    }

    /// Little-endian path bits: `true` means the current node is the left
    /// child; `false` means it is the right child.
    pub fn circuit_indices(&self) -> Vec<bool> {
        (0..self.depth())
            .map(|i| (self.leaf_index >> i) & 1 == 0)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OutbeV1;

    type Fr = <OutbeV1 as Suite>::Field;

    /// Appending a leaf to an empty tree gives the same root its (empty-tree)
    /// inclusion path resolves to.
    #[test]
    fn append_matches_inclusion_path() {
        let domain = Fr::from(42u64);
        let mut tree = Imt::<OutbeV1>::new(domain, Fr::zero(), 8).unwrap();
        let path = tree.empty_inclusion_path(0);
        let leaf = Fr::from(7u64);
        let (index, append) = tree.append(leaf).unwrap();
        assert_eq!(index, 0);
        assert_eq!(path.root(leaf).unwrap(), append.new_root);
        assert_eq!(path.circuit_indices(), vec![true; 8]);
    }

    #[test]
    fn domain_separates_empty_roots() {
        let root_a = Imt::<OutbeV1>::empty_root(Fr::from(1u64), Fr::zero(), 32).unwrap();
        let root_b = Imt::<OutbeV1>::empty_root(Fr::from(2u64), Fr::zero(), 32).unwrap();
        assert_ne!(root_a, root_b);
    }
}

#[cfg(test)]
mod retained_tree_tests {
    use super::*;
    use crate::OutbeV1;
    type Fr = <OutbeV1 as Suite>::Field;

    #[test]
    fn retained_paths_match_frontier_roots_and_history() {
        for empty_leaf in [Fr::zero(), Fr::from(99u64)] {
            let mut tree = Imt::<OutbeV1>::new(Fr::from(42u64), empty_leaf, 4).unwrap();
            let empty_root = tree.root();
            let mut roots = vec![empty_root];
            assert!(tree.inclusion_path(0).is_err());
            for i in 0..16u64 {
                let (index, change) = tree.append(Fr::from(i + 7)).unwrap();
                assert_eq!(index, i);
                assert_eq!(change.new_root, tree.root());
                roots.push(tree.root());
                for j in 0..=i {
                    let path = tree.inclusion_path(j).unwrap();
                    assert_eq!(path.root(tree.leaves()[j as usize]).unwrap(), tree.root());
                }
            }
            for (count, root) in roots.iter().enumerate() {
                assert_eq!(tree.root_at(count).unwrap(), *root);
                for i in 0..count {
                    let path = tree.inclusion_path_at(i as u64, count).unwrap();
                    assert_eq!(path.root(tree.leaves()[i]).unwrap(), *root);
                }
                assert!(tree.inclusion_path_at(count as u64, count).is_err());
            }
            let leaves = tree.leaves().to_vec();
            let root = tree.root();
            assert!(tree.append(Fr::from(100u64)).is_err());
            assert_eq!(tree.leaves(), leaves);
            assert_eq!(tree.root(), root);
            assert_eq!(tree.next_index(), 16);
            assert!(tree.root_at(17).is_err());
            assert!(tree.inclusion_path_at(0, 17).is_err());
            assert!(tree.inclusion_path(u64::MAX).is_err());
        }
    }

    #[test]
    fn depth_boundaries_and_zero_empty_leaf() {
        let domain = Fr::from(42u64);
        for depth in [0, 64, usize::MAX] {
            assert!(Imt::<OutbeV1>::new(domain, Fr::zero(), depth).is_err());
        }
        assert!(
            Imt::<OutbeV1>::frontier_append(domain, &[], 0, Fr::zero(), &[Fr::zero()]).is_err()
        );
        assert!(
            Imt::<OutbeV1>::root_from_inclusion_path(domain, Fr::zero(), 0, &[Fr::zero(); 64])
                .is_err()
        );
        for depth in [1, 32, 63] {
            let mut tree = Imt::<OutbeV1>::new(domain, Fr::zero(), depth).unwrap();
            let old_path = tree.empty_inclusion_path(0);
            tree.append(Fr::from(7u64)).unwrap();
            assert_eq!(old_path.siblings, tree.inclusion_path(0).unwrap().siblings);
            assert_eq!(old_path.root(Fr::from(7u64)).unwrap(), tree.root());
        }
    }
}
