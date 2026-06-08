// Single-NFT ownership proof circuit, per the privacy-preserving L2
// architecture sec.4.2.
//
// Used by wallets to prove ownership of one Spending Unit (or, with
// different inputs, one Tribute Draft) outside the multi-SU
// aggregation flow. The flat aggregation tier circuits
// (`outbe-flat-aggregation-circuit-n*`) embed N copies of the same
// constraint set inline -- they don't recursively verify proofs of
// this circuit.
//
// ## Public-input layout
//
// `[owner, nft_hash]`
//
// The on-chain verifier supplies these from the NFT's stored
// `derivedOwner` field and the entity hash reconstructed from the
// NFT's other fields (see `outbe_crypto_common::nft::compute_*_hash`).

use outbe_circuit_core::ownership;
use std::embedded_curve_ops::EmbeddedCurvePoint;

pub fn main(
    // Private inputs.
    //
    // For SU ownership: `pk` is the per-SU `shared_pk` derived via
    // App. A as a Grumpkin point; `nonce` is the `su_nonce` extracted
    // from the decrypted SRA receipt; `signature` is the 64-byte
    // Grumpkin Schnorr signature (`s || e`) over Poseidon2(nft_hash,
    // nonce).to_be_bytes() under `shared_sk`.
    //
    // For TD ownership: same shape, but with the wallet-rolled
    // per-TD Grumpkin keypair and `tribute_draft_nonce`.
    pk: EmbeddedCurvePoint,
    signature: [u8; 64],
    nonce: Field,
    // Public inputs.
    owner: pub Field,
    nft_hash: pub Field,
) {
    ownership::verify_ownership_per_su(pk, signature, nonce, owner, nft_hash);
}
