//! # outbe-zk-core
//!
//! The concrete cryptographic core of the Outbe zk circuits: BN254 as the
//! proving field, Grumpkin as its embedded curve, Poseidon2 as the hash and
//! Grumpkin Schnorr as the signature. There is no suite parameter — every
//! formula is a plain function over [`Fr`].
//!
//! - [`codec`] — typed values ↔ field elements ↔ bytes.
//! - [`hash`] — Poseidon2 plus the protocol formulas (owner commitment,
//!   entity hash, signing payload).
//! - [`imt`] — the append-only inclusion tree and its membership paths.
//! - [`keys`] — Grumpkin Schnorr and the NFT key encapsulation.
//! - [`shielded_pool`] — shared purpose tags and `hash_multi`.
//! - [`entity`] — the entity model the `#[derive(Entity)]` macro targets.
//! - [`zk`] — the circuit / backend seams.
//! - [`zkproof`] — canonical verifier-wire decoding.

#![forbid(unsafe_code)]

pub mod codec;
pub mod entity;
pub mod error;
pub mod hash;
pub mod imt;
pub mod keys;
pub mod shielded_pool;
pub mod zk;
pub mod zkproof;

/// The native proving field: BN254's scalar field, which is also Grumpkin's
/// base field (so curve coordinates are native field elements).
pub use ark_bn254::Fr;

pub use codec::{FieldElement, FieldEncode};
pub use error::Error;

/// `#[derive(Entity)]` — re-exported so a consumer needs one dependency.
pub use outbe_zk_core_derive::Entity;
