//! # outbe-l2-claims
//!
//! The L1-to-L2 claim contract, and nothing else.
//!
//! A *claim* is an NFT that moves from an L2 to L1 by proof. It is three
//! things, all under [`claims`]: the entity whose hash is `nft_hash`, the
//! binding formula whose result is `binding_hash`, and the fixed list of
//! public inputs a proof of that claim exposes (`claims/<name>/abi.json`).
//!
//! **This crate holds no verification key.** The keys, the committed roots and
//! `l2/manifest.toml` are [`outbe-l2-zk-canonical`], which depends on this
//! crate; the dependency runs one way only. That is the guarantee, and it is
//! structural rather than a cargo feature: a consumer that only hashes claims —
//! a prover, a TEE image whose identity is a measurement over its own bytes —
//! takes this crate, and registering an L2 cannot move a byte it compiles,
//! under any cargo invocation.
//!
//! It has no dependency on `outbe-zk-canonical` (the L1 circuits) or on
//! `outbe-zk-backend` either, in either direction and by design.
//!
//! [`outbe-l2-zk-canonical`]: https://docs.rs/outbe-l2-zk-canonical

#![forbid(unsafe_code)]

pub mod claims;

/// The cryptographic core, re-exported so a consumer that only folds claims
/// can depend on this crate alone and still reach `codec`, `hash`, `keys`,
/// `Entity` and `Error`.
pub use outbe_zk_core;

/// The public-input types, generated at build time from `claims/*/abi.json`.
/// Nothing here runs a toolchain and nothing here reads a key: `build.rs`
/// opens the claim ABIs and no other file. Re-exported through [`claims`],
/// which is where consumers should reach for it.
#[allow(unused_imports)] // shape-dependent: a claim of only integers needs no B256
#[allow(clippy::all)] // machine-generated from the claim ABIs; not hand-linted
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/l2_claims_generated.rs"));
}

pub use generated::CLAIM_ABIS;

/// One claim's public-input contract, as a build script can read it.
///
/// A build script cannot open another package's files by path, so
/// `outbe-l2-zk-canonical` takes this crate as a build-dependency and gates
/// every committed root's public ABI against [`CLAIM_ABIS`] — the contract
/// read from the crate that owns it.
pub struct ClaimAbi {
    /// The claim's directory name, as `l2/manifest.toml` spells it.
    pub name: &'static str,
    /// The literal `claims/<name>/abi.json` document, `include_str!`d.
    pub abi_json: &'static str,
    /// Leaf field words the ABI flattens to — the claim's
    /// `PUBLIC_INPUT_COUNT`.
    pub public_input_count: usize,
}
