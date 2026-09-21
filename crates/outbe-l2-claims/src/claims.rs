//! The claims. One module per `claims/<name>/abi.json`.
//!
//! By convention every claim exposes `owner`, `nft_hash` and `binding_hash` as
//! its first three public words and `merkle_root` as its last, so ownership,
//! binding and inclusion are checked the same way for every NFT.

pub mod tribute;
