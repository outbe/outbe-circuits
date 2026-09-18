//! # outbe-l2-demo
//!
//! The Rust side of one registered L2 tribute circuit —
//! `crates/outbe-l2-zk-canonical/l2/57005/tribute/1.0.0/`. This is what an L2
//! team clones: a witness builder, a prover, and tests that prove against the
//! key L1 verifies with.
//!
//! **Where the constants live.** The tree depth and the tree domain are *this
//! L2's*, not the claim's: they are defined here and in the root's `src/main.nr`
//! and nowhere else. `outbe-l2-zk-canonical` owns the claim — the entity, the
//! binding formula and the four public words — and deliberately owns no depth,
//! no domain and no owner commitment: word 0 is opaque to the claim, so the
//! `derive_owner` construction [`prove_tribute`] recomputes is this L2's too.
//! Two L2s can differ in all three under one claim.
//!
//! Nothing here depends on `outbe-zk-canonical`. An L2 has no business with L1
//! circuits, and the dependency graph says so. Two tests do read a committed
//! L1 *file* by path — the L1 manifest's proof-system pin, and one L1
//! verification key to reject a tribute proof under — which adds no crate, no
//! type and no call.

#![forbid(unsafe_code)]

pub mod draft;

use ark_bn254::Fr;
use ark_std::rand::Rng;

use outbe_l2_zk_canonical::claims::tribute::{PublicInputs, TributeDraftClaim};
use outbe_zk_core::codec::field_from_b256;
use outbe_zk_core::entity::Entity;
use outbe_zk_core::hash::{ascii_field, derive_owner, signing_payload};
use outbe_zk_core::imt::InclusionPath;
use outbe_zk_core::keys::{coords, Signer};
use outbe_zk_core::Error;

/// `Witness`, `EmbeddedCurvePoint` and the [`TributeDemo`] circuit marker,
/// generated at build time from the root's committed
/// `abi.json`, `circuit.vk` and `circuit.hash`. Editing the root and rebuilding
/// is the only way to change them.
#[allow(clippy::all)] // machine-generated from the root ABI; not hand-linted
mod generated {
    include!(concat!(env!("OUT_DIR"), "/demo_generated.rs"));
}

pub use generated::{EmbeddedCurvePoint, TributeDemo, Witness};

/// Depth of this L2's perpetual TributeDraft commitment tree.
///
/// The L2's own number, matching `[Field; 32]` / `[bool; 32]` in the root's
/// `main()`. Another L2 may register a root with another depth.
pub const DEPTH: usize = 32;

/// Domain separator for this L2's commitment-tree inner nodes.
///
/// The root hardcodes the same value as
/// `global TREE_DOMAIN: Field = 0x4f555442455f46554c4c5f43495243554954`, which
/// is `"OUTBE_FULL_CIRCUIT"` in ASCII — a frozen string, not a circuit name.
pub const TREE_DOMAIN: &str = "OUTBE_FULL_CIRCUIT";

/// [`TREE_DOMAIN`] as the field element the tree hashes with.
pub fn tree_domain() -> Fr {
    ascii_field(TREE_DOMAIN)
}

/// An empty commitment tree of this L2's depth, domain and empty leaf.
///
/// The empty-leaf value is the L2's convention too — it decides what an unused
/// slot hashes as, so it belongs next to the depth and the domain.
pub fn empty_tree() -> Result<outbe_zk_core::imt::Imt, Error> {
    outbe_zk_core::imt::Imt::new(tree_domain(), Fr::from(0u64), DEPTH)
}

/// Build the tribute witness and its public inputs: the reference prover.
///
/// The signer must be the claim's owner — `poseidon2([pk.x, pk.y, nonce])` is
/// recomputed and compared to `claim.owner`, so a witness that the circuit
/// would reject is refused here with [`Error::OwnerMismatch`] rather than after
/// a proving run. The signed message is `poseidon2([nft_hash, nonce,
/// binding_hash])` and nothing else, which is what makes the proof
/// unreplayable under another caller, draft, host chain or L2: `binding_hash`
/// is where `l2_chain_id` is folded.
///
/// `path` must be an inclusion path of this L2's own [`DEPTH`] and
/// [`tree_domain`] over the leaf `nft_hash` — the on-chain tree stores the
/// entity hash directly, so the leaf *is* the value the ownership constraint
/// binds. `merkle_root` is recomputed from the path rather than taken on trust.
pub fn prove_tribute<R: Rng>(
    rng: &mut R,
    claim: &TributeDraftClaim,
    signer: &Signer,
    binding: Fr,
    path: &InclusionPath,
) -> Result<(Witness, PublicInputs), Error> {
    if path.depth() != DEPTH {
        return Err(Error::Merkle(format!(
            "expected an inclusion path of depth {}, got {}",
            DEPTH,
            path.depth()
        )));
    }
    if path.domain != tree_domain() {
        return Err(Error::Merkle(
            "inclusion path uses the wrong tree domain".into(),
        ));
    }

    // Ownership: recompute the owner commitment from (pk, nonce), reject a
    // mismatch, then sign the §4.2 payload — the same constraint the circuit
    // enforces, checked before proving so the failure is legible.
    let seed = signer.owner_seed();
    let derived_owner = derive_owner(&seed.pk, seed.nonce)?;
    if derived_owner != field_from_b256(&claim.owner)? {
        return Err(Error::OwnerMismatch);
    }
    let nft_hash = claim.entity_hash()?;
    let payload = signing_payload(nft_hash, seed.nonce, binding)?;
    let signature = signer.sign(rng, payload)?;
    let (x, y) = coords(&seed.pk)?;

    // Inclusion: the leaf IS `nft_hash`. Recompute the root the circuit checks.
    let merkle_root = path.root(nft_hash)?;
    let merkle_path_siblings: [Fr; DEPTH] = path
        .siblings
        .as_slice()
        .try_into()
        .map_err(|_| Error::Merkle("siblings length".into()))?;
    let merkle_path_indices: [bool; DEPTH] = path
        .circuit_indices()?
        .try_into()
        .map_err(|_| Error::Merkle("indices length".into()))?;

    Ok((
        Witness {
            pk: EmbeddedCurvePoint { x, y },
            signature,
            nonce: seed.nonce,
            merkle_path_siblings,
            merkle_path_indices,
        },
        PublicInputs {
            owner: derived_owner,
            nft_hash,
            binding_hash: binding,
            merkle_root,
        },
    ))
}
