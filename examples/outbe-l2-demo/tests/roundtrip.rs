//! The prove-and-verify round trip against the *registered* key.
//!
//! One bb proof costs tens of seconds, so this is one test carrying every
//! proof-dependent assertion rather than six tests each paying for a proof:
//! the key the demo proves under is the key L1 verifies with, a valid proof
//! verifies, its combined encoding decodes back to the same public inputs, a
//! tampered word does not verify, the proof does not verify under another
//! circuit's key, and a preimage spelled out by hand — mostly literals, folded
//! with the bare `poseidon2` primitive and none of the claim's own hashing
//! helpers — reproduces public words 1 and 2 the way an independent verifier
//! would.

mod common;

use ark_bn254::Fr;

use outbe_l2_demo::{empty_tree, prove_tribute, TributeDemo};
use outbe_l2_zk_canonical::claims::tribute::{
    decode_public_inputs, public_words, PublicInputs, PUBLIC_INPUT_COUNT,
};
use outbe_l2_zk_canonical::{combined_len, encode_combined_proof, l2_keys, CircuitStatus, Claim};
use outbe_zk_backend::barretenberg::{Barretenberg, RawVerifier};
use outbe_zk_core::codec::{field_from_b256, field_from_be_bytes};
use outbe_zk_core::hash::poseidon2;
use outbe_zk_core::zk::{CircuitId, ProofGenerator, ProofVerifier};

#[test]
fn tribute_proof_verifies_under_the_registered_key() {
    // (a) The key this crate proves with IS the registered key. `VK_BYTES` is
    // `include_bytes!`d from the root by build.rs; `l2_keys` is the &'static
    // table the chain looks up. Equality here is what makes every assertion
    // below a statement about the key L1 actually verifies with.
    let keys = l2_keys(common::L2_CHAIN_ID, Claim::Tribute);
    assert_eq!(keys.len(), 1, "chain 57005 has one registered tribute key");
    assert_eq!(keys[0].version(), <TributeDemo as CircuitId>::VERSION);
    assert_eq!(keys[0].status(), CircuitStatus::Active);
    assert_eq!(keys[0].vk_bytes(), <TributeDemo as CircuitId>::VK_BYTES);
    assert_eq!(keys[0].vk_hash(), <TributeDemo as CircuitId>::VK_HASH);
    // The ACIR this crate carries belongs to that root. build.rs already fails
    // the build unless keccak256(ACIR) equals the root's circuit.hash; this
    // restates the tie against the committed file.
    assert_eq!(
        alloy_primitives::hex::encode(<TributeDemo as CircuitId>::CIRCUIT_HASH),
        include_str!("../../../crates/outbe-l2-zk-canonical/l2/57005/tribute/1.0.0/circuit.hash")
            .trim()
    );
    let vk = keys[0].vk_bytes();

    let mut rng = ark_std::test_rng();
    let f = common::fixture(&mut rng);
    let tree = empty_tree().unwrap();
    let path = tree.empty_inclusion_path(0);
    let (witness, public) = prove_tribute(&mut rng, &f.claim, &f.signer, f.binding, &path).unwrap();

    let bb = Barretenberg::default();
    let proof = ProofGenerator::<TributeDemo>::generate(&bb, &witness, &public).expect("bb prove");
    assert!(
        ProofVerifier::<TributeDemo>::verify(&bb, &public, &proof).unwrap(),
        "a valid tribute proof must verify"
    );

    // (b) The combined encoding decodes back to exactly what the prover made.
    // The decoder takes the key, not a baked length, so this is the on-chain
    // path: one decoder, any registered key.
    let combined = encode_combined_proof(&public_words(&public), &proof.proof, vk).unwrap();
    assert_eq!(
        combined.len(),
        combined_len(vk, PUBLIC_INPUT_COUNT).unwrap()
    );
    let decoded = decode_public_inputs(&combined, vk).unwrap();
    assert_eq!(decoded, public);

    // (c) A tampered public word must not verify. bb returns Ok(false) here,
    // not Err — a proof that fails to verify is an answer, not an error.
    let tampered = PublicInputs {
        binding_hash: public.binding_hash + Fr::from(1u64),
        ..public
    };
    assert!(
        !ProofVerifier::<TributeDemo>::verify(&bb, &tampered, &proof).unwrap(),
        "a tampered public word must not verify"
    );

    // (d) A proof verifies under its own key and no other. The chain looks a
    // key up by (l2_chain_id, claim, version) and hands *those* bytes to
    // barretenberg, so a lookup that returned some other registered key must
    // not produce a verification. The foreign key is an L1 one, read as raw
    // bytes by path out of a committed artifact — not a dependency on
    // `outbe-zk-canonical`: no Cargo edge, no type, no function, the same way
    // `proof_system.rs` already reads the L1 manifest. The demo still cannot
    // name an L1 circuit.
    //
    // bb answers `Ok(false)`, not `Err`. It rejects at the first disagreement,
    // and for a key belonging to another circuit that is the proof length the
    // key's header declares — it prints `invalid proof size. Expected 250, got
    // 274` and never reaches the pairing check. That is the honest strength of
    // this check, and its ceiling: every committed key in this repo belongs to
    // a *different* circuit, so none of them can put a same-length proof in
    // front of the pairing check. A key mutated to keep the length would not be
    // a key at all (bb fails to deserialize it), so it would prove less, not
    // more. A second registered L2 root of the same shape is what would test
    // key binding itself.
    const FOREIGN_VK: &[u8] = include_bytes!(
        "../../../crates/outbe-zk-canonical/resources/circuits/paynote/1.2.0/circuit.vk"
    );
    assert_ne!(FOREIGN_VK, vk, "the foreign key must be a different key");
    assert!(
        !bb.verify_combined(FOREIGN_VK, &combined).unwrap(),
        "a tribute proof must not verify under another circuit's key"
    );
    // Same proof, same bytes, own key: the rejection above was the key and
    // nothing else.
    assert!(
        bb.verify_combined(vk, &combined).unwrap(),
        "the same combined proof must verify under the registered key"
    );

    // (e) Verifier parity — an INDEPENDENT recomputation of the two folds.
    //
    // A verifier never sees the witness; it has raw values of its own. So this
    // section calls none of the three functions that produced
    // the prover's words — not `entity_hash` (the derive behind `nft_hash`),
    // not `binding` (behind `binding_hash`), not `TributeDraft::claim`. It
    // spells the two preimages out and folds them with the bare Poseidon2
    // primitive, which is the one thing the two paths must share: it is the
    // hash itself, not a helper that could encode the same mistake twice.
    // Reorder the derive's `pos` attributes, move the `len` prefix, or swap the
    // binding's limbs, and the prover follows silently while the spelling below
    // does not — that is the disagreement this catches and a determinism check
    // cannot.
    //
    // One preimage word cannot be a literal: `owner` commits to the fixture's
    // random key, so it is read off `f.claim` as a stored field, never through
    // a function that hashes it. Every other word, `id` included, is written
    // out by hand in the claim's fold order, as the decrypted draft behind
    // `common::fixture` carries it — `id`'s literal is only compared against
    // `f.claim.id` first, so a moved fixture fails loudly instead of quietly
    // agreeing with itself.
    //
    // Both `B256` words go through `field_from_b256`, the canonical decode the
    // claim itself uses: a value at or above the modulus must fail here exactly
    // as it fails in the derive, not be silently reduced onto some other
    // element that happens to agree.
    let draft_id = common::word(0xd1a5);
    assert_eq!(
        draft_id, f.claim.id,
        "the fixture's draft moved; these literals are the enclave's copy of it"
    );
    let owner_word = field_from_b256(&f.claim.owner).unwrap();
    let enclave_nft_hash = [
        owner_word,          // owner commitment
        Fr::from(20_263u64), // worldwide_day
        Fr::from(978u64),    // currency
        Fr::from(1_000u64),  // base: 1_000_000_042 micros / 10^6
        Fr::from(42u64),     // micro: the 10^-6 remainder
        Fr::from(2u64),      // len(su_ids) — the set's length prefix
        Fr::from(7u64),      // su_ids ascending, not in draft order
        Fr::from(99u64),
    ]
    .into_iter()
    .try_fold(field_from_b256(&draft_id).unwrap(), |acc, x| {
        poseidon2(&[acc, x])
    })
    .unwrap();
    // The binding's three byte slices are narrower than the modulus by
    // construction — a 20-byte address and two 16-byte limbs — so they decode
    // with the reducing `field_from_be_bytes`, which is what `binding` uses for
    // them too. Using the canonical decode here would be a different spelling
    // of the same value, not a stricter check.
    let enclave_binding_hash = poseidon2(&[
        Fr::from(1u64),                         // BINDING_DOMAIN v1
        field_from_be_bytes(&common::SENDER),   // the caller
        field_from_be_bytes(&draft_id.0[16..]), // draft id, low limb
        field_from_be_bytes(&draft_id.0[..16]), // draft id, high limb
        Fr::from(common::HOST_CHAIN_ID),
        Fr::from(common::L2_CHAIN_ID),
    ])
    .unwrap();

    // Public words 1 and 2, read out of the combined encoding with the on-chain
    // decoder rather than off the prover's struct. (b) already pinned the two to
    // each other, so this is not an independent path to the words — what it does
    // buy is that the words compared below are the ones the decoder yields for
    // the proof bb verified a moment ago.
    assert_eq!(
        decoded.nft_hash, enclave_nft_hash,
        "nft_hash: the enclave's preimage and the prover's fold disagree"
    );
    assert_eq!(
        decoded.binding_hash, enclave_binding_hash,
        "binding_hash: the enclave's preimage and the prover's binding disagree"
    );
    // And word 0 is the owner commitment stored in the draft, unchanged.
    assert_eq!(decoded.owner, owner_word);
}
