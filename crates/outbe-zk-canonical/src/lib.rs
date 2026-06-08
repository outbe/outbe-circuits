//! Canonical outbe Noir circuit descriptors.
//!
//! Authoritative on-chain identity source for the outbe L2 `zk_verify`
//! precompile. Consumed by the chain binary (the L2 execution layer)
//! which wraps each descriptor with chain-policy timing
//! (`activated_at_block` / `deprecated_at_block`) to form its
//! `CanonicalCircuit` table.
//!
//! Pure static data — no FFI, `no_std`. The heavy work of running
//! `nargo compile` + deriving VKs via Barretenberg + computing
//! `circuit_hash` happens in this workspace's
//! `xtask regenerate-canonical` command; the output is committed
//! straight into this file and `res/vks/*.vk`.
//!
//! ## Append-only
//!
//! Existing entries are **never modified**. New circuit revisions
//! (different source ⇒ different `circuit_hash`) get appended as
//! new descriptors. Deprecation of old descriptors is the chain's
//! concern (via `deprecated_at_block`); this crate just records what
//! exists.
//!
//! ## Regenerate
//!
//! After modifying a circuit under `crates/outbe-zk-circuit-noir/`:
//!
//! ```bash
//! cargo run --package xtask -- regenerate-canonical
//! ```
//!
//! That command:
//! 1. Compiles every circuit via `nargo`
//! 2. Computes `circuit_hash = keccak256(acir_bytes)` per circuit
//! 3. Derives `vk_bytes` via `noir_rs::barretenberg::verify::
//!    get_ultra_honk_keccak_verification_key`
//! 4. Computes `vk_hash = keccak256(vk_bytes)`
//! 5. Writes `vk_bytes` to `res/vks/<circuit_label>.vk`
//! 6. Regenerates this file's const declarations
//!
//! CI gates a `--check` invocation: regen + diff = fail on stale state.

#![no_std]

/// A canonical Noir circuit descriptor. All fields are content-derived
/// from the compiled ACIR + the chosen proving SRS (UltraHonkKeccak).
#[derive(Debug)]
pub struct CircuitDescriptor {
    /// ACIR bytecode hash: `keccak256(base64_decode(acir_bytecode))`.
    /// Stable identifier for this circuit at this source revision —
    /// this is what the chain's `zk_verify` precompile matches
    /// against to dispatch to the right VK.
    pub circuit_hash: [u8; 32],

    /// Human-readable label (e.g. "outbe.spending_unit.ownership").
    /// For logs / audit / `circuit_info` precompile output. NOT
    /// authoritative — the `circuit_hash` is.
    pub label: &'static str,

    /// Semver-style version string for human reading ("1.0.0").
    /// NOT authoritative; circuit_hash is the only identity that
    /// matters for verification.
    pub version: &'static str,

    /// Canonical UltraHonkKeccak verification key bytes, derived from
    /// this circuit + the production SRS. Used by the chain's
    /// `zk_verify` precompile (Noir + Barretenberg FFI) to verify
    /// proofs claimed against this circuit.
    pub vk_bytes: &'static [u8],

    /// Pre-computed `keccak256(vk_bytes)`. Lets contracts /
    /// `circuit_info` consumers cross-check VK provenance without
    /// re-hashing the (potentially tens-of-KB) VK bytes.
    pub vk_hash: [u8; 32],
}

// === BEGIN GENERATED — do not edit (run `cargo xtask regenerate-canonical`) ===

pub const FULL_PROOF: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "d3d2f1289b6c17a1172a263024f9e115072fd355a80ea1c0e84040407c49b125"
    ),
    label: "outbe.full_proof",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/full_proof.vk"),
    vk_hash: hex_literal::hex!("fd393d8a0d138c990a76e82d6dca14304ee4a7854e7d34c19e2b04e64d023ad7"),
};

pub const OWNERSHIP: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "18db006ac6304a0ff2f4b624a1e31961223184f3638ce421161196a6e1b19c57"
    ),
    label: "outbe.ownership",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/ownership.vk"),
    vk_hash: hex_literal::hex!("8b0dbc83792074e488b0b63ce62c1ddd08020ffa6fe980917a53ea63c8c08ccf"),
};

pub const ALL_CIRCUITS: &[&CircuitDescriptor] = &[&FULL_PROOF, &OWNERSHIP];
// === END GENERATED ===

/// Look up a descriptor by its ACIR `circuit_hash`. `O(n)` over a
/// small table — fine for the precompile path (n in single digits).
pub fn find_by_hash(circuit_hash: &[u8; 32]) -> Option<&'static CircuitDescriptor> {
    let mut i = 0;
    while i < ALL_CIRCUITS.len() {
        if &ALL_CIRCUITS[i].circuit_hash == circuit_hash {
            return Some(ALL_CIRCUITS[i]);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_hash_returns_none() {
        // An all-zero hash can't appear in ALL_CIRCUITS — keccak256 of
        // any non-empty ACIR is overwhelmingly unlikely to be zero — so
        // lookup must miss. Mirror of the "chain rejects unknown
        // circuits" safety guarantee from the consumer side.
        assert!(find_by_hash(&[0u8; 32]).is_none());
    }

    #[test]
    fn descriptor_size_invariants() {
        // After regeneration, every descriptor must have:
        //   - non-empty label
        //   - non-empty vk_bytes
        //   - keccak256(vk_bytes) == vk_hash (checked by xtask, not here)
        for d in ALL_CIRCUITS {
            assert!(!d.label.is_empty(), "label is empty");
            assert!(!d.vk_bytes.is_empty(), "vk_bytes is empty for {}", d.label);
        }
    }
}
