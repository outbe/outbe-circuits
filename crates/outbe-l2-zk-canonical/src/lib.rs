//! # outbe-l2-zk-canonical
//!
//! The L2 registry of the Outbe zk gate: the committed circuit roots under
//! `l2/`, the verification keys L1 verifies with, and the key-aware public
//! input decoders.
//!
//! The claim contract itself — the entities, their bindings, the claim ABIs
//! and the generated `PublicInputs` — is [`outbe_l2_claims`], which this crate
//! depends on and re-exports through [`claims`]. The split is the guarantee: a
//! consumer that only hashes claims takes that crate, and no verification key
//! can reach its binary under any cargo invocation. Nothing here is behind a
//! feature.
//!
//! This crate has no dependency on `outbe-zk-canonical` (the L1 circuits) or
//! on `outbe-zk-backend`, in either direction and by design: registering an L2
//! must not be able to touch an L1 circuit or its key, and a consumer that
//! only verifies claims takes this crate without taking barretenberg.

#![forbid(unsafe_code)]

use ark_bn254::Fr;
use outbe_zk_core::{codec, Error};

/// The claim contract, re-exported so a verifier needs one dependency: the
/// entities, `binding`, the claim ABIs and the generated `PublicInputs`.
pub use outbe_l2_claims;

/// The cryptographic core, re-exported so a consumer that only registers or
/// verifies claims can depend on this crate alone and still reach `codec`,
/// `hash`, `keys`, `Entity` and `Error`.
pub use outbe_zk_core;

/// The registered-key table and the key-aware decoders, generated at build
/// time from `outbe_l2_claims::CLAIM_ABIS` and `l2/manifest.toml`. Nothing
/// here runs a toolchain: `build.rs` reads committed files only. Re-exported
/// through [`claims`] and the crate root, which is where consumers should
/// reach for it.
#[allow(clippy::all)] // machine-generated from the claim ABIs; not hand-linted
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/l2_generated.rs"));
}

pub use generated::{l2_keys, Claim, L2_KEYS};

/// The claims: each one's contract re-exported from [`outbe_l2_claims`], plus
/// the `CLAIM` constant and the key-aware `decode_public_inputs`.
pub use generated::claims;

/// Lifecycle status of a registered L2 circuit version (see `l2/manifest.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitStatus {
    /// Accepts new offers.
    Active,
    /// Still verifies in-flight proofs; no new adoption.
    Deprecated,
    /// Retired. Never reaches [`L2_KEYS`] — `build.rs` drops the entry and
    /// requires its root to be deleted — so an offer naming it has no key.
    /// The variant exists because the manifest keeps the record.
    Revoked,
}

/// One registered L2 circuit version: the bytes L1 verifies a proof of this
/// claim with, plus their identity.
///
/// The key is compiled in from the committed root, so the set of keys a node
/// accepts changes only with a node release.
///
/// The fields are private and there is no public constructor: every `L2Key` a
/// consumer can reach came from [`L2_KEYS`], which `build.rs` derives from a
/// committed root. A caller cannot fabricate one around bytes of its own.
#[derive(Clone, Copy, Debug)]
pub struct L2Key {
    version: &'static str,
    status: CircuitStatus,
    vk_hash: [u8; 32],
    vk_bytes: &'static [u8],
}

impl L2Key {
    /// The L2's own semver for its circuit of this claim.
    pub fn version(&self) -> &'static str {
        self.version
    }

    /// Lifecycle status.
    pub fn status(&self) -> CircuitStatus {
        self.status
    }

    /// `keccak256(vk_bytes)`, derived by `build.rs` — never copied from the
    /// manifest, so it cannot disagree with the bytes.
    pub fn vk_hash(&self) -> [u8; 32] {
        self.vk_hash
    }

    /// UltraHonkKeccak verification key — all that verification needs.
    pub fn vk_bytes(&self) -> &'static [u8] {
        self.vk_bytes
    }
}

/// Every key one L2 chain has registered for one claim.
///
/// Sealed like [`L2Key`], and for the same reason: every row a consumer can
/// reach came from [`L2_KEYS`], so a caller cannot fabricate a table row that
/// points a chain and claim at keys of its own.
#[derive(Clone, Copy, Debug)]
pub struct L2ClaimEntry {
    chain_id: u64,
    claim: Claim,
    keys: &'static [L2Key],
}

impl L2ClaimEntry {
    /// The L2's chain id, as the L2Registry knows it.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Which claim these keys prove.
    pub fn claim(&self) -> Claim {
        self.claim
    }

    /// Versions in ascending order.
    pub fn keys(&self) -> &'static [L2Key] {
        self.keys
    }
}

/// A `bb-keccak-v1` verification key is exactly 59 words.
const VK_WORDS: usize = 3 + 28 * 2;

/// The eight `DefaultIO` pairing-accumulator words bb counts in the key
/// header's public-input count on top of the circuit's own.
const PAIRING_WORDS: usize = 8;

/// Read header word `index` of a verification key as a `u32`.
fn vk_header(vk: &[u8], index: usize) -> Result<usize, Error> {
    let word = &vk[index * 32..(index + 1) * 32];
    if word[..28].iter().any(|&byte| byte != 0) {
        return Err(Error::Proof(format!(
            "verification key header word {index} is not a u32"
        )));
    }
    Ok(u32::from_be_bytes(word[28..].try_into().expect("four bytes")) as usize)
}

/// Number of proof words a proof under this key carries.
///
/// This is the arithmetic every consumer of an L2 proof needs and the reason
/// one decoder serves every registered key: the size is a property of the key,
/// not a constant baked per circuit.
///
/// `DefaultIO (8) + Oink (18) + Sumcheck (9·log_n + 50) + Shplemini (3·log_n + 6)`,
/// including ZK masking data — UltraKeccakZK, bb 5.0.0-nightly.20260522.
pub fn proof_words(vk: &[u8], public_input_count: usize) -> Result<usize, Error> {
    if vk.len() != VK_WORDS * 32 {
        return Err(Error::Proof(format!(
            "verification key is {} bytes, expected {} ({VK_WORDS} words)",
            vk.len(),
            VK_WORDS * 32
        )));
    }
    let log_n = vk_header(vk, 0)?;
    if !(1..=28).contains(&log_n) {
        return Err(Error::Proof(format!(
            "verification key log circuit size {log_n} is out of range"
        )));
    }
    let declared = vk_header(vk, 1)?;
    if declared != public_input_count + PAIRING_WORDS {
        return Err(Error::Proof(format!(
            "verification key declares {declared} public inputs, the claim ABI has \
             {public_input_count} (+{PAIRING_WORDS} pairing accumulator words)"
        )));
    }
    Ok(82 + 12 * log_n)
}

/// Total length of a combined proof under this key: a four-byte public-input
/// count, the public words, then the proof words.
pub fn combined_len(vk: &[u8], public_input_count: usize) -> Result<usize, Error> {
    Ok(4 + (public_input_count + proof_words(vk, public_input_count)?) * 32)
}

/// Assemble a combined proof from ABI-ordered public words and proof words.
///
/// Written once here rather than generated per claim: the layout is the same
/// for every claim, and the public words come from the claim's own
/// `public_words`.
pub fn encode_combined_proof(
    public_inputs: &[Fr],
    proof: &[Vec<u8>],
    vk: &[u8],
) -> Result<Vec<u8>, Error> {
    let expected = proof_words(vk, public_inputs.len())?;
    if proof.len() != expected {
        return Err(Error::Proof(format!(
            "proof has {} words, expected {expected}",
            proof.len()
        )));
    }
    let mut combined = Vec::with_capacity(4 + (public_inputs.len() + expected) * 32);
    combined.extend_from_slice(&(public_inputs.len() as u32).to_be_bytes());
    for field in public_inputs {
        combined.extend_from_slice(&codec::field_to_be_bytes(field));
    }
    for (index, word) in proof.iter().enumerate() {
        if word.len() != 32 {
            return Err(Error::Proof(format!(
                "proof word {index} has {} bytes, expected 32",
                word.len()
            )));
        }
        combined.extend_from_slice(word);
    }
    Ok(combined)
}
