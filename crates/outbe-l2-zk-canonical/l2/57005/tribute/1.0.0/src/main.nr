// Tribute claim circuit — chain 57005, claim `tribute`, version 1.0.0.
//
// Self-contained by registry rule: no `path` dependency leaves this directory.
// The ownership constraint (sec.4.2) and the Merkle-inclusion helper are
// inlined from `outbe_circuit_core` so this root compiles from its own source
// alone; the only dependency is the tag-pinned `noir-lang/schnorr` crate.
//
// Tree depth (32) and the domain separator are this L2's own, not the claim's.

use std::embedded_curve_ops::EmbeddedCurvePoint;

// This L2's commitment-tree domain separator. The value is frozen: it is
// hashed into every inner node, so it is part of this root's ACIR and key.
// Its ASCII spelling is historical and names nothing in this repository.
global TREE_DOMAIN: Field = 0x4f555442455f46554c4c5f43495243554954; // ASCII "OUTBE_FULL_CIRCUIT"

pub fn main(
    // Private witness.
    pk: EmbeddedCurvePoint,
    signature: [u8; 64],
    nonce: Field,
    // Depth-32 Merkle inclusion path for the perpetual TD commitment tree.
    merkle_path_siblings: [Field; 32],
    merkle_path_indices: [bool; 32],
    // Public: the (owner, nft_hash, binding_hash) ownership prefix plus the
    // Merkle root the inclusion check resolves to.
    owner: pub Field,
    nft_hash: pub Field,
    binding_hash: pub Field,
    merkle_root: pub Field,
) {
    // Part 1: sec.4.2 ownership proof. Owner commitment + Grumpkin Schnorr
    // over Poseidon3(nft_hash, nonce, binding_hash).
    verify_ownership_per_su(pk, signature, nonce, owner, nft_hash, binding_hash);

    // Part 2: Merkle inclusion of `nft_hash` against `merkle_root`.
    let computed_merkle_root = merkle_root_from_indices(
        TREE_DOMAIN,
        nft_hash,
        merkle_path_siblings,
        merkle_path_indices,
    );
    assert(
        computed_merkle_root == merkle_root,
        "merkle_root mismatch: inclusion proof failed",
    );
}

/// `Poseidon2(a, b, c)` — a full rate block: absorb-permute, then squeeze-permute.
fn hash_3(inputs: [Field; 3]) -> Field {
    let iv: Field = 55340232221128654848; // 3 << 64
    let s1 = std::hash::poseidon2_permutation([inputs[0], inputs[1], inputs[2], iv]);
    std::hash::poseidon2_permutation(s1)[0]
}

/// Compute the Poseidon3 owner commitment from a Grumpkin public key
/// and a nonce -- `Poseidon3(pk.x, pk.y, nonce)`.
fn compute_ownership(pk: EmbeddedCurvePoint, nonce: Field) -> Field {
    hash_3([pk.x, pk.y, nonce])
}

/// Verify a Grumpkin Schnorr signature over `message`.
fn verify_schnorr_grumpkin(
    pk: EmbeddedCurvePoint,
    signature: [u8; 64],
    message: [u8; 32],
) -> bool {
    schnorr::verify_signature(pk, signature, message)
}

/// sec.4.2 ownership-proof constraint set.
fn verify_ownership_per_su(
    pk: EmbeddedCurvePoint,
    signature: [u8; 64],
    nonce: Field,
    owner: Field,
    nft_hash: Field,
    binding_hash: Field,
) {
    assert(!pk.is_infinite(), "pk is the Grumpkin identity point");
    let x_cubed = pk.x * pk.x * pk.x;
    assert(
        pk.y * pk.y == x_cubed - 17,
        "pk is not on the Grumpkin curve (y^2 != x^3 - 17)",
    );

    let computed_owner = compute_ownership(pk, nonce);
    assert(
        computed_owner == owner,
        "owner mismatch: Poseidon3(pk, nonce) != public owner",
    );

    let pre_hash_fr: Field = hash_3([nft_hash, nonce, binding_hash]);
    let pre_hash_bytes: [u8; 32] = pre_hash_fr.to_be_bytes();

    let signature_ok = verify_schnorr_grumpkin(pk, signature, pre_hash_bytes);
    assert(
        signature_ok,
        "signature mismatch: Schnorr/Grumpkin over Poseidon3(nft_hash, nonce, binding_hash) failed",
    );
}

/// Inner-node hash: `Poseidon2(domain, left, right)`.
fn merkle_hash(domain: Field, left: Field, right: Field) -> Field {
    hash_3([domain, left, right])
}

/// Compute a Merkle root from a sibling path and explicit little-endian
/// left/right flags: `true` places the current node on the left.
fn merkle_root_from_indices<let N: u32>(
    domain: Field,
    leaf: Field,
    sibling_path: [Field; N],
    path_indices: [bool; N],
) -> Field {
    let mut node = leaf;

    for i in 0..N {
        let sibling = sibling_path[i];
        let (left, right) = if path_indices[i] {
            (node, sibling)
        } else {
            (sibling, node)
        };
        node = merkle_hash(domain, left, right);
    }

    node
}

// ---------------------------------------------------------------------------
// Tests
//
// `#[test]` functions are not part of the binary's ACIR, so nothing below
// changes the committed `circuit.vk` / `circuit.hash` — `cargo xtask l2 verify`
// proves that, not this comment.
//
// The witness is a pinned vector: one run of the Rust reference prover
// (`examples/outbe-l2-demo`, `common::fixture` + `prove_tribute` seeded with
// `ark_std::test_rng()`). A Grumpkin Schnorr signature cannot be produced
// in-circuit, so it has to come from outside; pinning the prover's output also
// makes these tests a cross-implementation check — the Rust owner commitment,
// signing payload and Merkle root are what the circuit here recomputes.
mod tests {
    use super::{main, merkle_hash, TREE_DOMAIN};
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    global PK_X: Field = 0x23a01bd8dde9f43571956bdd153442ec16d9dbe28d999668bae510803926af63;
    global PK_Y: Field = 0x169c843b626b1388a7c9acea8540ec2cf79284b2316d2c3118c802f739498f4d;
    global NONCE: Field = 0x0d004a3ec16148a06e4327024d35da4596668851b471e9e85623ab712940117e;
    global OWNER: Field = 0x12393360ebc9790f0b5c994be25c01e1c4c5235749e2c50ef47aa1086b9e7380;
    global NFT_HASH: Field = 0x0cd417fe14474a94860d5b4ec115b2d98c7d22fb0ca5a307e44a7e6a728b88cd;
    global BINDING_HASH: Field = 0x1e513b0014baafbe84e2d75b128b4ae26732df2a71bf8bb07dbe98a825370676;
    // The root the Rust side computed for this leaf at index 0 of an empty
    // depth-32 tree. Pinned rather than recomputed here: the circuit's own
    // Merkle check is what has to reproduce it.
    global MERKLE_ROOT: Field = 0x05a2315bd2cfad40b1cf135671c63c343bf4eb5c0d334ccaecfd4a4118f73c24;
    global SIGNATURE: [u8; 64] = [
        15, 110, 91, 133, 5, 242, 210, 189, 67, 220, 73, 48, 37, 178, 20, 149, 177, 20, 98, 164,
        203, 60, 244, 245, 154, 229, 14, 164, 113, 143, 130, 96, 111, 179, 196, 108, 73, 217, 49,
        92, 246, 225, 208, 223, 109, 154, 192, 48, 33, 237, 3, 24, 102, 158, 28, 167, 234, 65, 141,
        85, 195, 122, 178, 201,
    ];

    fn pk() -> EmbeddedCurvePoint {
        EmbeddedCurvePoint::new(PK_X, PK_Y)
    }

    /// Sibling path for index 0 of an empty tree: the empty leaf is `0` and
    /// every level above is the empty subtree below it, doubled.
    fn empty_path() -> [Field; 32] {
        let mut path = [0; 32];
        for level in 1..32 {
            path[level] = merkle_hash(TREE_DOMAIN, path[level - 1], path[level - 1]);
        }
        path
    }

    #[test]
    fn valid_witness_satisfies_the_circuit() {
        main(
            pk(),
            SIGNATURE,
            NONCE,
            empty_path(),
            [true; 32],
            OWNER,
            NFT_HASH,
            BINDING_HASH,
            MERKLE_ROOT,
        );
    }

    #[test(should_fail)]
    fn wrong_owner_commitment_fails() {
        main(
            pk(),
            SIGNATURE,
            NONCE,
            empty_path(),
            [true; 32],
            OWNER + 1,
            NFT_HASH,
            BINDING_HASH,
            MERKLE_ROOT,
        );
    }

    #[test(should_fail)]
    fn bad_signature_fails() {
        let mut signature = SIGNATURE;
        signature[0] ^= 0xff;
        main(
            pk(),
            signature,
            NONCE,
            empty_path(),
            [true; 32],
            OWNER,
            NFT_HASH,
            BINDING_HASH,
            MERKLE_ROOT,
        );
    }

    #[test(should_fail)]
    fn wrong_merkle_root_fails() {
        main(
            pk(),
            SIGNATURE,
            NONCE,
            empty_path(),
            [true; 32],
            OWNER,
            NFT_HASH,
            BINDING_HASH,
            MERKLE_ROOT + 1,
        );
    }
}
