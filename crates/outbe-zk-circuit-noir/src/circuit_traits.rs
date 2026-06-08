//! Backend-agnostic ZK circuit abstractions.
//!
//! These traits used to live in `outbe-crypto-common` alongside the witness
//! types. The witness types moved into `outbe-crypto-common` during the
//! consensus-binding extraction; the backend traits stayed in the
//! circuit repo because they describe how a Noir-style backend
//! produces and verifies proofs, which is not a consensus concern.
//!
//! Today this crate is the only backend implementation. If a second
//! one ever lands (e.g. Plonky3, Halo2), promote this module into its
//! own crate and depend on it from both.

/// A generated zero-knowledge proof with its public inputs.
pub trait Proof {
    /// Returns the serialized proof bytes as a base58 string.
    fn proof(&self) -> String;

    /// Returns the public inputs used to generate this proof.
    fn public_inputs(&self) -> Vec<String>;
}

/// Metadata about a compiled ZK circuit: hash, version, and type identifier.
#[derive(Clone, Debug)]
pub struct ZKCircuitVersion {
    /// Hash of the compiled circuit bytecode.
    pub circuit_hash: String,
    /// Semantic version of the circuit.
    pub circuit_version: String,
    /// Human-readable circuit type identifier (e.g. "noir", "noir-ownership").
    pub circuit_type: String,
}

/// Abstraction over a ZK circuit backend that can generate and verify proofs.
///
/// # Type Parameters
///
/// * `Config` — backend-specific configuration for circuit setup.
/// * `P` — the proof type produced by this circuit.
pub trait ZKCircuit<Config, P: Proof + Sized> {
    /// The witness type accepted by this circuit for proof generation.
    type Witness;

    /// Initialize the circuit from the given configuration.
    fn setup(c: Config) -> anyhow::Result<Self>
    where
        Self: Sized;

    /// Return version metadata for the loaded circuit.
    fn version(&self) -> ZKCircuitVersion;

    /// Generate a proof from the given witness.
    fn prove(&self, witness: Self::Witness) -> anyhow::Result<P>;

    /// Verify a proof, returning `true` if valid.
    fn verify(&self, proof: P) -> anyhow::Result<bool>;
}
