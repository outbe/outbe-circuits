//! # outbe-crypto-common
//!
//! Consensus-binding primitives for the outbe protocol. Owns the
//! **single source of truth** for every hash formula and witness type
//! that has to agree byte-for-byte across the wallet (off-chain),
//! the chain's on-chain precompiles, and the Noir ZK circuits.
//!
//! ## Binding policy
//!
//! | Module       | Binds to                                  | Hardfork required? |
//! | ------------ | ----------------------------------------- | ------------------ |
//! | `hash`       | Internal building block (Poseidon2 / Poseidon3 / Poseidon4 / Poseidon5). Not directly bound. | N/A — changing these would break everything below. |
//! | `ownership`  | The ZK circuit (Noir source).             | Yes — new ACIR → new canonical descriptor. Not exposed in Solidity. |
//! | `merkle`     | The ZK circuit Merkle-path semantics.     | Yes — coordinated circuit release. |
//! | `witness`    | The ZK circuit public-input layout.       | Yes — coordinated circuit + wallet release. |
//!
//! **Any change to a published function's output bytes is a major-version bump.**

#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use)]

pub mod error;
pub mod hash;
pub mod merkle;
pub mod ownership;
pub mod witness;

pub use error::OutbeCryptoError;
