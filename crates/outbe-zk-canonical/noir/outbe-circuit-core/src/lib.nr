// Shared library for ZK proof circuits.
// Modules:
// - `merkle_tree`: domain-separated Merkle node hash and root resolution from
//   a sibling path.
// - `tags`: base purpose tags; a circuit derives its own via
//   `tags::tag(ITS_DOMAIN, TAG_X)`.

pub mod merkle_tree;
pub mod hash;
pub mod tags;
pub mod types;
