//! The L2-side draft and its projection onto the claim.
//!
//! An L2 stores whatever its product needs. L1 hashes only
//! [`TributeDraftClaim`] — six members in a pinned fold order. The projection
//! is the L2's responsibility; the hash is not. Everything this file drops
//! (`state`, `created_at`, `note`, the per-unit metadata) is invisible to the
//! proof, and everything it keeps must be byte-identical to the values the
//! verifying side folds, or the hashes disagree and the proof is rejected.

use alloy_primitives::B256;

use outbe_l2_zk_canonical::claims::tribute::TributeDraftClaim;
use outbe_zk_core::codec::sort_set;
use outbe_zk_core::Error;

/// One spending unit as this L2 stores it: the id L1 hashes plus bookkeeping
/// it does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendingUnit {
    /// The id that reaches the claim. Must be `< FR_MODULUS`: mint it as a
    /// Poseidon2 output, never as 32 random bytes or a keccak digest.
    pub id: B256,
    /// Which settlement batch consumed it. L2-only.
    pub batch: u32,
}

/// Where a draft is in this L2's own lifecycle. L2-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DraftState {
    Open,
    Submitted,
    Settled,
}

/// A tribute draft as this L2 stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TributeDraft {
    /// The draft id. Must be `< FR_MODULUS`, same as every other `B256` that
    /// reaches the claim.
    pub id: B256,
    /// `poseidon2([pk.x, pk.y, nonce])` for the key that signs the proof.
    pub owner: B256,
    /// Worldwide day the tribute is offered for.
    pub worldwide_day: u64,
    /// ISO-4217 numeric currency code.
    pub currency: u16,
    /// The amount in 10^-6 units — one number here, two members in the claim.
    pub amount_micros: u128,
    /// The spending units this tribute consumes, in whatever order the L2
    /// happens to hold them.
    pub spending_units: Vec<SpendingUnit>,
    /// L2-only from here down: never hashed, never proved.
    pub state: DraftState,
    pub created_at: u64,
    pub note: String,
}

impl TributeDraft {
    /// Project onto the claim L1 hashes.
    ///
    /// Two things an implementer must get right and nothing checks for them:
    /// the amount splits into whole units and a 10^-6 remainder below
    /// 1_000_000 (two spellings of one amount otherwise), and `su_ids` is a
    /// canonical set — strictly ascending by field value, so sorted and
    /// de-duplicated. [`sort_set`] does the second; the split does the first.
    pub fn claim(&self) -> Result<TributeDraftClaim, Error> {
        let ids: Vec<B256> = self.spending_units.iter().map(|unit| unit.id).collect();
        Ok(TributeDraftClaim {
            id: self.id,
            owner: self.owner,
            worldwide_day: self.worldwide_day,
            currency: self.currency,
            base: u64::try_from(self.amount_micros / 1_000_000)
                .map_err(|_| Error::Proof("tribute amount overflows u64 base units".into()))?,
            micro: (self.amount_micros % 1_000_000) as u64,
            su_ids: sort_set(&ids)?,
        })
    }
}
