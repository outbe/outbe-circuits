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
//! frozen artifacts under `resources/circuits/` (L1) and `l2/` (L2); normal builds
//! do not invoke `nargo` or `bb`. Per circuit it derives Rust `Witness` / `PublicInputs`
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

/// The circuit seams live in the core (`outbe-protocol`), so a noir backend can be
/// generic over circuits without depending on this crate. Re-exported here for
/// convenience and the build-generated identity implementations.
pub use outbe_protocol::protocol::zk::CircuitId;

/// Depth of the perpetual TributeDraft commitment tree — the chain's
/// `CommitmentWindowBase.TREE_DEPTH` and the `demo_tribute` circuit's Merkle path
/// length. The [`outbe_protocol::protocol::imt::Imt`] is depth-agnostic;
/// this pins the canonical depth the Demo Tribute circuit is built for.
pub const INCLUSION_DEPTH: usize = 32;

/// Lifecycle status of an L1 circuit release (see `circuits/manifest.toml`).
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

/// One frozen L1 circuit release in the in-code registry
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

/// A package selected by an L2 chain version, identified by its verification key.
///
/// Unlike L1 releases, L2 packages have no independent version or lifecycle status.
/// A stable chain version pins the key; mutable versions can refresh it in place.
#[derive(Clone, Copy, Debug)]
pub struct L2Circuit {
    /// Package path relative to `l2/<chain_id>/`.
    pub path: &'static str,
    /// Pinned `keccak256(vk_bytes)` verification identity.
    pub vk_hash: [u8; 32],
    /// Complete UltraHonkKeccak verification key.
    pub vk_bytes: &'static [u8],
}

/// Packages selected by an exact L2 `(chain_id, version)`, in declaration order.
///
/// Unknown chains or versions return an empty slice, never a latest-version fallback.
/// References share private package descriptors across chain versions. Lookup allocates nothing.
pub fn l2_circuits(chain_id: u64, version: &str) -> &'static [&'static L2Circuit] {
    noir::L2_CHAIN_INDEX
        .binary_search_by(|entry| (entry.0, entry.1).cmp(&(chain_id, version)))
        .map_or(&[], |index| noir::L2_CHAIN_INDEX[index].2)
}

/// Rust types generated at build time from committed frozen artifacts.
///
/// L1 modules describe the latest active release; the append-only
/// [`CIRCUIT_REGISTRY`](noir::CIRCUIT_REGISTRY) contains every non-revoked L1 release.
/// L2 modules use their Nargo package names. Their descriptive `VERSION` is the latest
/// registered chain version using that package, not an independent package release.
/// Exact L2 chain-version selection is exposed through [`l2_circuits`].
#[allow(dead_code)]
#[allow(clippy::all)] // machine-generated by build.rs from the noir ABIs; not hand-linted
pub mod noir {
    include!(concat!(env!("OUT_DIR"), "/noir_generated.rs"));
}
