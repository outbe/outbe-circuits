// Shared library for ZK proof circuits.
// Modules:
// - `ownership`: sec.4.2 single-NFT ownership proof helpers --
//   Poseidon3 owner commitment + Grumpkin Schnorr signature over
//   Poseidon2(nft_hash, nonce).
// - `inclusion`: Merkle inclusion path verification.

pub mod ownership;
pub mod inclusion;
pub mod hash;
pub mod types;
