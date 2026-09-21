//! Poseidon2 and the protocol's hash formulas.
//!
//! Two hashing operations cover every Outbe need:
//!
//! - [`poseidon2`] — fixed-arity single-shot. Used for the owner commitment,
//!   the binding hash, Merkle nodes, and the signing payload.
//! - [`iterate`] — iterated 2-to-1 over a seed, `fold(seed, |acc, x|
//!   poseidon2([acc, x]))`. Used for entity hashes; `iterate(seed, [])`
//!   returns `seed`.
//!
//! [`nft_hash`] and [`signing_payload`] are consensus preimages: their element
//! order is frozen. None of the formulas here folds in a domain constant.
//! [`derive_owner`] is not one of them — the owner commitment is each L2's own
//! construction (`outbe-l2-claims`'s `TributeDraftClaim::owner` treats it
//! as an opaque field element), and this is the one the reference demo in
//! `examples/outbe-l2-demo` uses. The submission binding is *not* here either:
//! it names an L2 chain id, so it lives with its claim, in
//! `outbe-l2-claims`.

use ark_ff::PrimeField;

use crate::error::Error;
use crate::keys::{coords, PublicKey};
use crate::Fr;

/// BN254 Poseidon2 via `outbe-poseidon` — bit-identical to noir's in-circuit
/// `poseidon2` (the sponge over the bb `poseidon2_permutation`). One sponge
/// covers every arity, so unlike the circom Poseidon1 it predates there are no
/// per-width parameter sets. The sponge cannot fail, so the `Result` is always
/// `Ok` — kept so callers keep one uniform fallible hashing shape.
pub fn poseidon2(inputs: &[Fr]) -> Result<Fr, Error> {
    use outbe_poseidon::PoseidonHasher as _;
    outbe_poseidon::Poseidon2::new()
        .hash(inputs)
        .map_err(|error| Error::Hash(error.to_string()))
}

/// Iterated 2-to-1 hash: `state = poseidon2([state, x])` folded over `body`,
/// seeded at `seed`. `iterate(seed, [])` returns `seed`.
pub fn iterate(seed: Fr, body: &[Fr]) -> Result<Fr, Error> {
    let mut state = seed;
    for x in body {
        state = poseidon2(&[state, *x])?;
    }
    Ok(state)
}

/// `derivedOwner = poseidon2([pk.x, pk.y, nonce])`.
pub fn derive_owner(pk: &PublicKey, nonce: Fr) -> Result<Fr, Error> {
    let (x, y) = coords(pk)?;
    poseidon2(&[x, y, nonce])
}

/// Entity hash: iterated hash seeded at `id` over `body`.
pub fn nft_hash(id: Fr, body: &[Fr]) -> Result<Fr, Error> {
    iterate(id, body)
}

/// The Schnorr message: `poseidon2([nft_hash, nonce, binding])`.
pub fn signing_payload(nft_hash: Fr, nonce: Fr, binding: Fr) -> Result<Fr, Error> {
    poseidon2(&[nft_hash, nonce, binding])
}

/// A short ASCII tag as one field element (big-endian, reduced).
pub fn ascii_field(value: &str) -> Fr {
    Fr::from_be_bytes_mod_order(value.as_bytes())
}
