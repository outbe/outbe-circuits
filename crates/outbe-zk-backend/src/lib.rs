//! Noir proving backend for the canonical Outbe circuits.
//!
//! Layering: the circuit *seams* live in the core `outbe-protocol`
//! ([`Circuit`](outbe_protocol::protocol::zk::Circuit) with its prove-side
//! `witness_inputs` and verify-side `public_inputs`, plus
//! [`CircuitId`](outbe_protocol::protocol::zk::CircuitId) /
//! [`CircuitSuite`](outbe_protocol::protocol::zk::CircuitSuite)). This crate is
//! **generic over any circuit** implementing those seams — it does not depend on
//! the concrete `outbe-zk-canonical` (only its tests/benches do). It adds the
//! noir-toolchain coupling that can't be published (acir/acvm via git, native
//! barretenberg): a shared ACVM witness-solving core ([`witness`]) and the
//! [`barretenberg`] UltraHonkKeccak prover/verifier (FFI, on-device).
//!
//! Both consume [`witness::solved_witness`] (the ACVM-solved witness) and
//! [`witness::public_inputs`], and implement the core
//! [`ProofGenerator`](outbe_protocol::protocol::zk::ProofGenerator) /
//! [`ProofVerifier`](outbe_protocol::protocol::zk::ProofVerifier) seams.

pub mod barretenberg;
pub mod witness;
