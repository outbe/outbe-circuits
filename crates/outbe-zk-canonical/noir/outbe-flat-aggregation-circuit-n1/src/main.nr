// Flat per-SU ownership aggregation, tier N=1.
//
// Verifies N copies of `outbe_circuit_core::ownership::verify_ownership_per_su`
// inline (no recursive proof verification). One of 7 canonical tiers
// the wallet picks based on the number of SUs being aggregated into
// a TributeDraft. The shared `verify_ownership_per_su` keeps the
// constraint set bit-identical across the standalone ownership
// circuit, the full-proof circuit, and every flat aggregation tier.
//
// ## Public-input layout
//
// `[owner_0, nft_hash_0, ..., owner_{N-1}, nft_hash_{N-1}, binding_hash]`
//
// The on-chain verifier supplies each `(owner_i, nft_hash_i)` pair
// from the corresponding SU NFT's `derivedOwner` field and the
// entity hash reconstructed via `outbe_protocol::nft::compute_*_hash`.
// The trailing `binding_hash` is shared by every slot and recomputed
// on-chain via precompile `0x0210` from `msg.sender`,
// `tributeDraftId`, and `block.chainid` -- it makes the aggregation
// proof non-replayable across callers, tribute drafts, and chains.

use outbe_circuit_core::ownership;
use std::embedded_curve_ops::EmbeddedCurvePoint;

global N: u32 = 1;

pub fn main(
    pk: [EmbeddedCurvePoint; N],
    signature: [[u8; 64]; N],
    nonce: [Field; N],
    // 2N (owner, nft_hash) slots followed by one shared binding_hash.
    public_inputs: pub [Field; 2 * N + 1],
) {
    let binding_hash = public_inputs[2 * N];
    for i in 0..N {
        let owner = public_inputs[2 * i];
        let nft_hash = public_inputs[2 * i + 1];
        ownership::verify_ownership_per_su(
            pk[i],
            signature[i],
            nonce[i],
            owner,
            nft_hash,
            binding_hash,
        );
    }
}
