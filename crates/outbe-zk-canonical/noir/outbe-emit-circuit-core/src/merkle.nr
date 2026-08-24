use crate::hash::{p, TAG_EMPTY, TAG_NODE};

pub global MERKLE_DEPTH: u32 = 20;

pub fn empty_leaf(pool: Field) -> Field {
    p(TAG_EMPTY, [pool])
}

pub fn node(level: u32, left: Field, right: Field) -> Field {
    p(TAG_NODE, [level as Field, left, right])
}

pub fn merkle_root(leaf: Field, leaf_index: u32, path: [Field; 20]) -> Field {
    let mut current = leaf;
    let mut index = leaf_index;
    for level in 0..20 {
        if index & 1 == 0 {
            current = node(level, current, path[level]);
        } else {
            current = node(level, path[level], current);
        }
        index = index >> 1;
    }
    current
}
