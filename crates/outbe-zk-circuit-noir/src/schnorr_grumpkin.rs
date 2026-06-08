//! Grumpkin Schnorr key + signing helpers (production path).
//!
//! Wraps the `barretenberg-rs` FFI we already depend on. Same FFI
//! implementation barretenberg's `std::embedded_curve_ops::
//! multi_scalar_mul` foreign call uses in-circuit, so off-chain
//! signatures produced here verify bit-identically against the
//! in-circuit `schnorr::verify_signature` constraint set.
//!
//! Usable from any consumer that already has `outbe-zk-circuit-noir`
//! in its dep graph (wallet, CLI, mobile-integration). The
//! `testing` module in this crate re-exports these for circuit-level
//! tests; the names are identical.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use barretenberg_rs::{backends::FfiBackend, BarretenbergApi};
use rand::rngs::OsRng;
use rand::RngCore;

/// 32-byte LE encoding of an `Fr` (right-padded with zeros if short).
pub fn fr_to_le32(value: &Fr) -> [u8; 32] {
    let le = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let n = le.len().min(32);
    out[..n].copy_from_slice(&le[..n]);
    out
}

/// 32-byte BE encoding of an `Fr` (the format `schnorr::verify_signature`
/// expects for its `message: [u8; 32]` argument inside the circuit, and
/// the format `barretenberg-rs::schnorr_construct_signature` consumes
/// on the signer side).
pub fn fr_to_be32(value: &Fr) -> [u8; 32] {
    let be = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let n = be.len().min(32);
    out[(32 - n)..].copy_from_slice(&be[..n]);
    out
}

/// Grumpkin keypair, suitable for in-circuit Schnorr verify.
#[derive(Debug, Clone, Copy)]
pub struct GrumpkinKey {
    /// 32-byte secret-key bytes (the layout
    /// `barretenberg-rs::schnorr_compute_public_key` consumes).
    pub sk_bytes: [u8; 32],
    /// Grumpkin public-key x coordinate (Fr, fits one BN254 scalar).
    pub pk_x: Fr,
    /// Grumpkin public-key y coordinate (Fr).
    pub pk_y: Fr,
}

/// Sample a fresh Grumpkin keypair from OS randomness.
///
/// The 32 random bytes are reduced modulo the Grumpkin scalar field
/// order (= BN254's base field `Fq`) before being handed to
/// `barretenberg-rs`. bb 5.x's `schnorr_compute_public_key` aborts
/// the process with an uncatchable C++ exception on any input
/// `>= q_Grumpkin`. With 256-bit raw randomness ~63% of unreduced
/// rolls would trip that path; reducing here makes the helper safe
/// for every consumer (test code in particular).
pub fn random_grumpkin_key() -> anyhow::Result<GrumpkinKey> {
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    // Reduce mod q_Grumpkin in-place. We model q as BN254 `Fq`
    // (Grumpkin's scalar field is BN254's base field by
    // construction).
    let reduced = ark_bn254::Fq::from_be_bytes_mod_order(&sk_bytes);
    let be = ark_ff::PrimeField::into_bigint(reduced);
    let be_bytes = ark_ff::BigInteger::to_bytes_be(&be);
    let mut padded = [0u8; 32];
    let off = 32 - be_bytes.len().min(32);
    padded[off..].copy_from_slice(&be_bytes[be_bytes.len().saturating_sub(32)..]);
    derive_grumpkin_public_key(&padded)
}

/// Derive a Grumpkin public key from raw 32-byte secret-key bytes via
/// the barretenberg FFI.
pub fn derive_grumpkin_public_key(sk_bytes: &[u8; 32]) -> anyhow::Result<GrumpkinKey> {
    let mut api = api_handle()?;
    let resp = api
        .schnorr_compute_public_key(sk_bytes)
        .map_err(|e| anyhow::anyhow!("schnorr_compute_public_key: {e}"))?;
    // `public_key` carries the Grumpkin point with each coord as a
    // 32-byte big-endian field encoding (barretenberg's wire format).
    let pk_x = Fr::from_be_bytes_mod_order(&resp.public_key.x);
    let pk_y = Fr::from_be_bytes_mod_order(&resp.public_key.y);
    Ok(GrumpkinKey {
        sk_bytes: *sk_bytes,
        pk_x,
        pk_y,
    })
}

/// Sign the 32-byte BE encoding of an `Fr` digest with Grumpkin
/// Schnorr. Returns the 64-byte `s || e` layout the Noir
/// `schnorr::verify_signature` expects.
pub fn schnorr_sign_be(sk_bytes: &[u8; 32], digest_fr: &Fr) -> anyhow::Result<[u8; 64]> {
    let message = fr_to_be32(digest_fr);
    let mut api = api_handle()?;
    let resp = api
        .schnorr_construct_signature(&message, sk_bytes)
        .map_err(|e| anyhow::anyhow!("schnorr_construct_signature: {e}"))?;
    if resp.s.len() != 32 || resp.e.len() != 32 {
        anyhow::bail!(
            "schnorr_construct_signature returned unexpected lengths: s={}, e={}",
            resp.s.len(),
            resp.e.len()
        );
    }
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&resp.s);
    sig[32..].copy_from_slice(&resp.e);
    Ok(sig)
}

fn api_handle() -> anyhow::Result<BarretenbergApi<FfiBackend>> {
    let backend = FfiBackend::new().map_err(|e| anyhow::anyhow!("FfiBackend: {e}"))?;
    Ok(BarretenbergApi::new(backend))
}
