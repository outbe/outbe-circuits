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
// `[owner, nft_hash, binding_hash]`
//
// The on-chain verifier supplies `owner`/`nft_hash` from the NFT's
// stored `derivedOwner` field and the entity hash reconstructed from
// the NFT's other fields (see `outbe_protocol::nft::compute_*_hash`),
// and `binding_hash` via precompile `0x0210` from `msg.sender`,
// `tributeDraftId`, and `block.chainid`.

use outbe_circuit_core::ownership;
use std::embedded_curve_ops::EmbeddedCurvePoint;

pub fn main(
    // Private inputs.
    //
    // For SU ownership: `pk` is the per-SU `shared_pk` derived via
    // App. A as a Grumpkin point; `nonce` is the `su_nonce` extracted
    // from the decrypted SRA receipt; `signature` is the 64-byte
    // Grumpkin Schnorr signature (`s || e`) over Poseidon3(nft_hash,
    // nonce, binding_hash).to_be_bytes() under `shared_sk`.
    //
    // For TD ownership: same shape, but with the wallet-rolled
    // per-TD Grumpkin keypair and `tribute_draft_nonce`.
    pk: EmbeddedCurvePoint,
    signature: [u8; 64],
    nonce: Field,
    // Public inputs.
    owner: pub Field,
    nft_hash: pub Field,
    binding_hash: pub Field,
) {
    ownership::verify_ownership_per_su(pk, signature, nonce, owner, nft_hash, binding_hash);
}
