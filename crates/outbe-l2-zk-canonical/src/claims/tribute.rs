//! The tribute claim: the entity behind `nft_hash` and the binding formula
//! behind `binding_hash`.
//!
//! This is the one definition. Every consumer of this crate — a prover, a
//! verifier, the benchmarks in `examples/outbe-l2-demo` — folds the same struct
//! through the same derive, so a draft hashed by a prover and the same draft
//! recomputed elsewhere cannot disagree.
//!
//! The public-input ABI that completes the claim is `claims/tribute/abi.json`:
//! `owner, nft_hash, binding_hash, merkle_root`, four field words in that
//! order. A breaking change to that list is a new claim name, not a new
//! version of this one.

/// The claim's public-input contract, generated from `claims/tribute/abi.json`:
/// `owner, nft_hash, binding_hash, merkle_root`, four field words in that
/// order. [`decode_public_inputs`] takes the verification key alongside the
/// proof, so one decoder serves every registered tribute key.
pub use crate::generated::tribute::{
    alloy, decode_public_inputs, public_words, PublicInputs, CLAIM, PUBLIC_INPUT_COUNT,
};

use alloy_primitives::B256;
use ark_bn254::Fr;
use outbe_zk_core::codec::field_from_be_bytes;
use outbe_zk_core::hash::poseidon2;
use outbe_zk_core::{Entity, Error};

/// A tribute draft, as the claim hashes it.
///
/// The fold order is the consensus preimage and is pinned by `pos`, not by
/// declaration order:
///
/// ```text
/// nft_hash = iterate(id, [owner, worldwide_day, currency, base, micro,
///                         len(su_ids), su_0, …, su_n-1])
/// ```
///
/// where `iterate(seed, xs) = fold(seed, |s, x| poseidon2([s, x]))`. The
/// `len` prefix comes from the canonical set encoding of `su_ids` and makes
/// the vector boundary unambiguous.
///
/// **Field fit.** Every `B256` member is a BN254 scalar carried in 32 bytes,
/// not an arbitrary 256-bit value: it must be strictly below
/// [`outbe_zk_core::codec::FR_MODULUS`]. Hashing decodes through
/// `field_from_be_bytes_canonical`, so a value at or above the modulus fails
/// with [`Error::NonCanonical`] instead of being silently reduced onto a
/// different element. An L2 must therefore mint draft ids and SU ids as field
/// elements in the first place (a Poseidon2 output, say), never as 32 random
/// bytes or a keccak digest: the modulus is about `0.189 * 2^256`, so a
/// uniform 32-byte word is in range only ~18.9% of the time and roughly
/// **four in five** of them are rejected.
#[derive(Entity, Clone, Debug, PartialEq, Eq)]
pub struct TributeDraftClaim {
    /// The L2's draft id; seeds the hash. Must be `< FR_MODULUS`.
    #[outbe(id)]
    pub id: B256,
    /// The L2's owner commitment: public input 0 of the proof, and body
    /// position 0 of this fold. The claim treats it as an opaque field
    /// element — how an L2 constructs it, and whether any nonce goes into it
    /// at all, is that L2's own business and is no part of this contract. A
    /// verifier compares word 0 against the value carried here and never
    /// recomputes it. Like every other `B256` member it must be
    /// `< FR_MODULUS`: hashing decodes it canonically, so a value at or above
    /// the modulus fails with [`Error::NonCanonical`] rather than being
    /// reduced onto a different element.
    #[outbe(body, pos = 0)]
    pub owner: B256,
    /// Worldwide day the tribute is offered for.
    #[outbe(body, pos = 1)]
    pub worldwide_day: u64,
    /// ISO-4217 numeric currency code.
    #[outbe(body, pos = 2)]
    pub currency: u16,
    /// Whole units of the amount; the base unit is 10^6 `micro`.
    #[outbe(body, pos = 3)]
    pub base: u64,
    /// The 10^-6 remainder of the amount, `0..=999_999`. A producer that lets
    /// it reach 10^6 has two spellings for one amount; the hash does not
    /// enforce the bound, the producer must.
    #[outbe(body, pos = 4)]
    pub micro: u64,
    /// The spending units this tribute consumes. Folded as a canonical set —
    /// strictly ascending by field value, so sorted and de-duplicated; use
    /// [`outbe_zk_core::codec::sort_set`] to normalise. Each element must be
    /// `< FR_MODULUS`.
    #[outbe(body, pos = 5)]
    pub su_ids: Vec<B256>,
}

/// Version/domain separator folded into [`binding`] as its first preimage
/// element. `1` is the V1 submission-binding interface; it separates
/// interfaces, not arities, so appending `l2_chain_id` does not move it.
pub const BINDING_DOMAIN: u64 = 1;

/// `binding_hash` — the word that ties a proof to one caller, one draft, one
/// host chain and one L2.
///
/// ```text
/// poseidon2([BINDING_DOMAIN, sender, draft_id_lo128, draft_id_hi128,
///            host_chain_id, l2_chain_id])
/// ```
///
/// The draft id uses its established two-limb encoding, **low limb first**;
/// that is independent of the three-limb encoding U256 amounts use. The L2
/// chain id is the sixth element, so a proof made for one L2 does not verify
/// as another L2's even under a byte-identical circuit — and folding it here
/// rather than exposing it as a fifth public input leaves the circuit, its
/// ABI and its key untouched.
///
/// The circuit treats the result as opaque: it only folds it into the signed
/// message. This function is the single definition both sides of that
/// comparison must call: whoever builds the witness computes it, and whoever
/// checks the proof recomputes it from its own copy of `(sender, draft_id,
/// host_chain_id, l2_chain_id)` and compares it against public word 2 — the
/// contract a verifier upholds, not something this crate performs.
pub fn binding(
    sender: &[u8; 20],
    draft_id: &[u8; 32],
    host_chain_id: u64,
    l2_chain_id: u64,
) -> Result<Fr, Error> {
    poseidon2(&[
        Fr::from(BINDING_DOMAIN),
        field_from_be_bytes(sender),
        field_from_be_bytes(&draft_id[16..]),
        field_from_be_bytes(&draft_id[..16]),
        Fr::from(host_chain_id),
        Fr::from(l2_chain_id),
    ])
}
