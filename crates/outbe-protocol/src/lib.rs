//! # outbe-protocol
//!
//! Outbe's consensus primitives over BN254, Grumpkin, Poseidon2 and Schnorr.
//!
//! - [`primitive`] — concrete cryptographic operations and protocol hash formulas.
//! - [`codec`] — canonical field and key encoding at byte/ABI boundaries.
//! - [`protocol`] — entity hashing, ownership, signers, Merkle trees and proof interfaces.
//!
//! Circuit and backend traits remain extensible; their cryptographic field and
//! signature representation are fixed to the production protocol.

#![forbid(unsafe_code)]

pub mod codec;
pub mod error;
pub mod primitive;
pub mod protocol;

pub use ark_bn254::Fr;
pub use codec::{FieldElement, FieldEncode};
pub use error::Error;
