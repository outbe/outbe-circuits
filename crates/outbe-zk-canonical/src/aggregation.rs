//! Flat aggregation, wired to the build-generated per-tier noir circuits.
//!
//! The generated aggregation circuits are **const-N** (one circuit per tier:
//! `FlatAggregationN1`, `…N2`, `…N4`, …), each with a struct-of-arrays
//! `Witness { pk: [_; N], signature: [_; N], nonce: [_; N] }` and
//! `PublicInputs { public_inputs: [Fr; 2N + 1] }`.
//!
//! Each "slot" is an ownership `(Witness, PublicInputs)` pair (see
//! [`crate::ownership`]). Assembly pads `N` real slots up to a tier with
//! canonical padding slots (a real derived owner over `nft_hash = 0`), then
//! `try_into`s the slot arrays into the per-tier struct-of-arrays. Padding is
//! distinguished by `nft_hash == 0`, which the chain skips — *not* by a zeroed
//! owner, which the circuit's per-slot constraint would reject.
//!
//! Generic over any [`CircuitSuite`]. Two entry points:
//!   * [`FlatAggregation`] — implemented on every per-tier marker, for callers
//!     that know the tier at compile time
//!     (`FlatAggregationN4::assemble::<S, _>(…)`).
//!   * [`AggregationTier`] — a runtime selector mapping a real slot count to the
//!     *exact* circuit ([`AggregationTier::for_count`]) and assembling into a
//!     tier-erased [`AnyTier`].
//!
//! The per-tier surface — the [`FlatAggregation`] impls, the [`AnyTier`] /
//! [`AggregationTier`] enums, and the latter's tier→circuit dispatch — is all
//! generated from the single [`tiers!`] table below, so adding a tier is a
//! one-line edit there.

use ark_ff::Zero;
use ark_std::rand::Rng;

use outbe_protocol::error::Error;
use outbe_protocol::primitive::curve::coords;
use outbe_protocol::primitive::signature::SignatureScheme;
use outbe_protocol::Suite;

use crate::noir::ownership_proof::{
    PublicInputs as OwnershipPublicInputs, Witness as OwnershipWitness,
};
use crate::noir::EmbeddedCurvePoint;
use crate::{CircuitId, CircuitSuite};

/// One aggregation slot: a built ownership `(Witness, PublicInputs)` pair.
/// Real slots come from [`crate::ownership::Provable::derive_ownership_witness`];
/// padding slots are produced by [`FlatAggregation::padding_slot`].
pub type Slot = (OwnershipWitness, OwnershipPublicInputs);

/// Assemble a runtime `Vec` of ownership [`Slot`]s into a fixed-tier
/// aggregation circuit's generated `(Witness, PublicInputs)`. Implemented by
/// every per-tier marker, so the assembly entry point lives on the circuit type
/// — like [`Circuit`] / [`CircuitId`] — instead of one free function per tier.
/// Generic over the [`CircuitSuite`] whose ops build the padding slots.
///
/// [`Circuit`]: outbe_protocol::protocol::zk::Circuit
pub trait FlatAggregation<S: CircuitSuite>: Sized {
    /// Slot capacity `N` of this tier.
    const TIER: usize;
    /// Generated struct-of-arrays witness for this tier.
    type Witness;
    /// Generated `2N + 1` public inputs for this tier.
    type PublicInputs;

    /// One canonical padding slot: fresh embedded-curve key, `nonce = 0`,
    /// `nft_hash = 0`, `owner = derive_owner(pad_pk, 0)`, and a Schnorr
    /// signature over `signing_payload(0, 0, binding)`.
    ///
    /// Tier-independent default. Satisfies the circuit's per-slot ownership
    /// constraint — which enforces `owner == Poseidon3(pk, nonce)` for *every*
    /// slot, padding included, so the owner is the real derived value, never
    /// zero. The slot is recognized as empty by its `nft_hash == 0`.
    fn padding_slot<R: Rng>(rng: &mut R, binding: S::Field) -> Result<Slot, Error> {
        let (sk, pk) = <S as Suite>::Signature::keypair(rng);
        let nonce = S::Field::zero();
        let nft_hash = S::Field::zero();
        let owner = S::derive_owner(&pk, nonce)?;
        let payload = S::signing_payload(nft_hash, nonce, binding)?;
        let signature = <S as Suite>::Signature::sign(rng, &sk, payload)?;

        let (x, y) = coords::<S::Curve>(&pk)?;
        let witness = OwnershipWitness {
            pk: EmbeddedCurvePoint { x, y },
            signature,
            nonce,
        };
        let public = OwnershipPublicInputs {
            owner,
            nft_hash,
            binding_hash: binding,
        };
        Ok((witness, public))
    }

    /// Flatten padded slots into this tier's `2N + 1` public-input vector
    /// (`[owner_i, nft_hash_i …, binding]`). Tier- and suite-independent default.
    /// Every slot — real or padding — carries its actual `(owner, nft_hash)`:
    /// the circuit constrains `owner == Poseidon3(pk, nonce)` for *all* slots,
    /// so padding is distinguished by `nft_hash == 0`, never by a zeroed owner.
    fn public_inputs_from_slots(slots: &[Slot], binding: S::Field) -> Vec<S::Field> {
        let mut v = Vec::with_capacity(2 * slots.len() + 1);
        for (_, public) in slots {
            v.push(public.owner);
            v.push(public.nft_hash);
        }
        v.push(binding);
        v
    }

    /// Pad `real` up to [`TIER`](FlatAggregation::TIER) with canonical padding
    /// slots, then convert into the generated `(Witness, PublicInputs)` pair.
    /// Errors with [`Error::TierOverflow`] if `real.len() > TIER`.
    fn assemble<R: Rng>(
        rng: &mut R,
        real: Vec<Slot>,
        binding: S::Field,
    ) -> Result<(Self::Witness, Self::PublicInputs), Error>;
}

/// Generate the entire per-tier surface from one table of
/// `Variant => module, Marker, N, 2N+1` rows:
///   * a [`FlatAggregation`] impl per tier marker (pad → struct-of-arrays);
///   * the tier-erased [`AnyTier`] enum + its `tier` / `public_inputs` readers;
///   * the [`AggregationTier`] selector enum + its `capacity` / `label` /
///     `circuit_hash` / `vk_hash` / `assemble` dispatch.
///
/// Every arm is mechanically identical across tiers, so this is the single
/// source of truth — adding a tier is one new row.
macro_rules! tiers {
    ($($variant:ident => $module:ident, $marker:ident, $n:literal, $arity:literal);+ $(;)?) => {
        $(
            impl<S: CircuitSuite> FlatAggregation<S> for crate::noir::$module::$marker {
                const TIER: usize = $n;
                type Witness = crate::noir::$module::Witness;
                type PublicInputs = crate::noir::$module::PublicInputs;

                fn assemble<R: Rng>(
                    rng: &mut R,
                    real: Vec<Slot>,
                    binding: S::Field,
                ) -> Result<(Self::Witness, Self::PublicInputs), Error> {
                    if real.len() > $n {
                        return Err(Error::TierOverflow(real.len()));
                    }
                    let mut slots = real;
                    while slots.len() < $n {
                        slots.push(<Self as FlatAggregation<S>>::padding_slot(rng, binding)?);
                    }
                    let fields = <Self as FlatAggregation<S>>::public_inputs_from_slots(&slots, binding);

                    // Slots → struct-of-arrays. `slots.len() == $n` after
                    // padding, so each `try_into` to a `[_; $n]` array succeeds.
                    let mut pks = Vec::with_capacity($n);
                    let mut sigs = Vec::with_capacity($n);
                    let mut nonces = Vec::with_capacity($n);
                    for (w, _) in &slots {
                        pks.push(w.pk);
                        sigs.push(w.signature);
                        nonces.push(w.nonce);
                    }
                    let witness = crate::noir::$module::Witness {
                        pk: pks.try_into().map_err(|_| Error::TierOverflow($n))?,
                        signature: sigs.try_into().map_err(|_| Error::TierOverflow($n))?,
                        nonce: nonces.try_into().map_err(|_| Error::TierOverflow($n))?,
                    };
                    let public = crate::noir::$module::PublicInputs {
                        public_inputs: <[S::Field; $arity]>::try_from(fields)
                            .map_err(|_| Error::TierOverflow($n))?,
                    };
                    Ok((witness, public))
                }
            }
        )+

        /// A tier-erased assembled aggregation: the generated `(Witness,
        /// PublicInputs)` pair for whichever tier [`AggregationTier::assemble`]
        /// selected. The witness types are suite-independent (BN254-concrete),
        /// so this carries no `S`.
        #[allow(clippy::large_enum_variant)] // tier-erased result; the size spread across tiers is inherent
        pub enum AnyTier {
            $( $variant(crate::noir::$module::Witness, crate::noir::$module::PublicInputs), )+
        }

        impl AnyTier {
            /// Which tier this was assembled into.
            pub fn tier(&self) -> AggregationTier {
                match self {
                    $( AnyTier::$variant(..) => AggregationTier::$variant, )+
                }
            }

            /// The flattened `2N + 1` public inputs of the assembled aggregation.
            /// `AnyTier` is suite-erased, so this is the circuit's concrete
            /// proving field (`ark_bn254::Fr`) rather than a suite's `S::Field`.
            pub fn public_inputs(&self) -> Vec<ark_bn254::Fr> {
                match self {
                    $( AnyTier::$variant(_, p) => p.public_inputs.to_vec(), )+
                }
            }
        }

        /// The canonical aggregation tiers as a runtime value — one per
        /// generated per-tier circuit. Selecting a tier *is* selecting the exact
        /// circuit: [`label`](AggregationTier::label) /
        /// [`circuit_hash`](AggregationTier::circuit_hash) resolve to that
        /// circuit's [`CircuitId`] identity (suite-independent), and
        /// [`assemble`](AggregationTier::assemble) builds its witness for a
        /// suite `S`.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum AggregationTier {
            $( $variant, )+
        }

        impl AggregationTier {
            /// This tier's slot capacity `N`.
            pub fn capacity(self) -> usize {
                match self {
                    $( Self::$variant => $n, )+
                }
            }

            /// The canonical dotted label of this tier's circuit.
            pub fn label(self) -> &'static str {
                match self {
                    $( Self::$variant => <crate::noir::$module::$marker as CircuitId>::LABEL, )+
                }
            }

            /// The canonical `circuit_hash` of this tier's circuit.
            pub fn circuit_hash(self) -> [u8; 32] {
                match self {
                    $( Self::$variant => <crate::noir::$module::$marker as CircuitId>::CIRCUIT_HASH, )+
                }
            }

            /// The canonical `vk_hash` of this tier's circuit.
            pub fn vk_hash(self) -> [u8; 32] {
                match self {
                    $( Self::$variant => <crate::noir::$module::$marker as CircuitId>::VK_HASH, )+
                }
            }

            /// Assemble `real` into *this* tier's circuit for suite `S`, padding
            /// up to its capacity. Errors with [`Error::TierOverflow`] if
            /// `real.len() > capacity()`. Pick the tier first with
            /// [`AggregationTier::for_count`].
            pub fn assemble<S: CircuitSuite, R: Rng>(
                self,
                rng: &mut R,
                real: Vec<Slot>,
                binding: S::Field,
            ) -> Result<AnyTier, Error> {
                Ok(match self {
                    $( Self::$variant => {
                        let (w, p) = <crate::noir::$module::$marker as FlatAggregation<S>>::assemble(rng, real, binding)?;
                        AnyTier::$variant(w, p)
                    } )+
                })
            }
        }
    };
}

tiers! {
    N1  => flat_aggregation_n1,  FlatAggregationN1,  1,  3;
    N2  => flat_aggregation_n2,  FlatAggregationN2,  2,  5;
    N4  => flat_aggregation_n4,  FlatAggregationN4,  4,  9;
    N8  => flat_aggregation_n8,  FlatAggregationN8,  8,  17;
    N16 => flat_aggregation_n16, FlatAggregationN16, 16, 33;
    N32 => flat_aggregation_n32, FlatAggregationN32, 32, 65;
    N64 => flat_aggregation_n64, FlatAggregationN64, 64, 129;
}

impl AggregationTier {
    /// The smallest tier whose capacity fits `count` real slots, or `None` if
    /// it exceeds the largest tier (64). Range-keyed (not a per-tier symmetry),
    /// so it stays handwritten rather than table-generated.
    pub fn for_count(count: usize) -> Option<Self> {
        Some(match count {
            0..=1 => Self::N1,
            2 => Self::N2,
            3..=4 => Self::N4,
            5..=8 => Self::N8,
            9..=16 => Self::N16,
            17..=32 => Self::N32,
            33..=64 => Self::N64,
            _ => return None,
        })
    }
}
