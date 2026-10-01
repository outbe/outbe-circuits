//! Concrete canonical circuit and witness types for the Outbe protocol.
//!
//! The core (`outbe-protocol`) defines the seams — the
//! [`Circuit`](outbe_protocol::protocol::zk::Circuit),
//! [`ProofGenerator`](outbe_protocol::protocol::zk::ProofGenerator), and
//! [`ProofVerifier`](outbe_protocol::protocol::zk::ProofVerifier) traits plus
//! concrete BN254/Grumpkin/Poseidon2/Schnorr formulas. This crate supplies the statements built
//! on top of them, generated from the vendored noir circuits.
//!
//! The noir circuits and Rust witness types use the same concrete BN254 field
//! and 64-byte Grumpkin Schnorr signatures as the protocol.
//!
//! The [`noir`] module is **build-generated** at compile time from committed
//! frozen artifacts in `resources/circuits/`; normal builds do not invoke
//! `nargo` or `bb`. Per circuit it derives Rust `Witness` / `PublicInputs`
//! types, a marker type with a
//! [`Circuit`](outbe_protocol::protocol::zk::Circuit) impl + a
//! [`CircuitId`] identity impl, and the canonical descriptor
//! constants (`LABEL` / `VERSION` / `CIRCUIT_HASH` / `BYTECODE_B64` /
//! `VK_BYTES` / `VK_HASH`).
//!
//! The `.nr` circuits remain the source of truth.

pub mod demo_tribute;
pub mod emit_mint;
pub mod ownership;
pub mod paynote;
pub mod paynote_merge;
pub mod pledge;

/// The circuit seams live in the core (`outbe-protocol`), so a noir backend can be
/// generic over circuits without depending on this crate. Re-exported here for
/// convenience and the build-generated identity implementations.
pub use outbe_protocol::protocol::zk::CircuitId;

/// Depth of the perpetual TributeDraft commitment tree — the chain's
/// `CommitmentWindowBase.TREE_DEPTH` and the `demo_tribute` circuit's Merkle path
/// length. The [`outbe_protocol::protocol::imt::Imt`] is depth-agnostic;
/// this pins the canonical depth the Demo Tribute circuit is built for.
pub const INCLUSION_DEPTH: usize = 32;

/// Lifecycle status of a registered circuit version (see `circuits/manifest.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitStatus {
    /// Accepts new proofs.
    Active,
    /// Still verifies in-flight proofs; no new adoption. Keeps its VK; the
    /// freeze step drops its bytecode (a proving artifact).
    Deprecated,
    /// Obsolete: no longer verifies (normal sunset or emergency kill-switch).
    /// The freeze step drops its VK too, and it is absent from
    /// [`CIRCUIT_REGISTRY`](noir::CIRCUIT_REGISTRY) — the manifest keeps the
    /// record (`circuit_hash`).
    Revoked,
}

/// One frozen, released circuit version in the in-code registry
/// ([`noir::CIRCUIT_REGISTRY`]). Append-only: new versions are added and old
/// ones kept until revoked, so a verifier can accept old + new concurrently.
///
/// This is the **verification** view — it carries only the VK, since
/// verification needs only the VK (+ public inputs + proof). The ACIR bytecode
/// is a *proving* artifact and is kept only for the **active** version, on its
/// `noir::<module>::BYTECODE_B64` const; old versions drop their bytecode (a
/// retired prover ships its own).
#[derive(Clone, Copy, Debug)]
pub struct RegistryEntry {
    /// Canonical dotted label (the logical statement), e.g. `outbe.ownership`.
    pub label: &'static str,
    /// Semver version of this artifact.
    pub version: &'static str,
    /// Lifecycle status.
    pub status: CircuitStatus,
    /// Proof system these bytes verify under (the bb pin / verifier routing key).
    pub proof_system: &'static str,
    /// `keccak256(acir bytecode)` — the binary identity (preserved in the
    /// manifest after the bytecode itself is dropped).
    pub circuit_hash: [u8; 32],
    /// `keccak256(vk_bytes)`.
    pub vk_hash: [u8; 32],
    /// UltraHonkKeccak verification key — all that verification needs.
    pub vk_bytes: &'static [u8],
}

/// One frozen circuit version explicitly enabled for an L2 chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L2CircuitVersion {
    /// Semver version of the frozen circuit artifact.
    pub version: &'static str,
    /// `keccak256(acir bytecode)`, matching a [`RegistryEntry::circuit_hash`].
    pub circuit_hash: [u8; 32],
    /// `keccak256(vk_bytes)`, matching a [`RegistryEntry::vk_hash`].
    pub vk_hash: [u8; 32],
}

/// All circuit versions explicitly enabled for one external L2 chain.
#[derive(Clone, Copy, Debug)]
pub struct L2ChainEntry {
    pub chain_id: u64,
    pub circuits: &'static [L2CircuitVersion],
}

/// Enabled versions for an L2 chain, or an empty slice if none are configured.
///
/// Bindings are explicit: a new circuit release does not change them. Deprecated
/// circuits may remain enabled for verification; revoked circuits cannot be bound.
pub fn l2_circuits(chain_id: u64) -> &'static [L2CircuitVersion] {
    noir::L2_CIRCUITS_REGISTRY
        .binary_search_by_key(&chain_id, |entry| entry.chain_id)
        .map_or(&[], |index| noir::L2_CIRCUITS_REGISTRY[index].circuits)
}

/// Rust types generated at build time from the **frozen** circuit artifacts
/// listed in `circuits/manifest.toml` (witness + public-input shapes + canonical
/// identity for the latest active version of each circuit, plus the full
/// append-only [`CIRCUIT_REGISTRY`](noir::CIRCUIT_REGISTRY) over every version
/// and the explicitly enabled [`L2_CIRCUITS_REGISTRY`](noir::L2_CIRCUITS_REGISTRY)).
#[allow(dead_code)]
#[allow(clippy::all)] // machine-generated by build.rs from the noir ABIs; not hand-linted
pub mod noir {
    include!(concat!(env!("OUT_DIR"), "/noir_generated.rs"));
}
