//! The build-generated surface: the key table and the key-aware decoder.
//!
//! No toolchain and no network — everything here reads the committed root the
//! same way `cargo build` does.
//!
//! All of it is the `l2-keys` half. The claim half — entity, `binding`, the
//! generated `PublicInputs` — is `tests/tribute.rs`, which compiles either way;
//! see `the_enclaves_half_needs_no_registry` there.
#![cfg(feature = "l2-keys")]

use ark_bn254::Fr;
use outbe_l2_zk_canonical::claims::tribute::{
    alloy, decode_public_inputs, public_words, PublicInputs, CLAIM, PUBLIC_INPUT_COUNT,
};
use outbe_l2_zk_canonical::{
    combined_len, encode_combined_proof, l2_keys, CircuitStatus, Claim, L2_KEYS,
};
use outbe_zk_core::codec::FR_MODULUS;
use outbe_zk_core::Error;

/// The registered demo key, straight from the committed root.
const DEMO_VK: &[u8] = include_bytes!("../l2/57005/tribute/1.0.0/circuit.vk");

fn demo_key() -> &'static outbe_l2_zk_canonical::L2Key {
    let keys = l2_keys(57005, Claim::Tribute);
    assert_eq!(keys.len(), 1, "chain 57005 has one registered tribute key");
    &keys[0]
}

fn sample() -> PublicInputs {
    PublicInputs {
        owner: Fr::from(11u64),
        nft_hash: Fr::from(22u64),
        binding_hash: Fr::from(33u64),
        merkle_root: Fr::from(44u64),
    }
}

/// A combined proof with the right shape for `vk`. The proof words are filler:
/// nothing here verifies a proof, it exercises the public-word envelope.
fn combined(public: &PublicInputs, vk: &[u8]) -> Vec<u8> {
    let words = public_words(public);
    let proof_words = (combined_len(vk, PUBLIC_INPUT_COUNT).unwrap() - 4) / 32 - PUBLIC_INPUT_COUNT;
    let proof = vec![[7u8; 32].to_vec(); proof_words];
    encode_combined_proof(&words, &proof, vk).unwrap()
}

#[test]
fn the_table_holds_the_committed_key() {
    let key = demo_key();
    assert_eq!(key.version(), "1.0.0");
    assert_eq!(key.status(), CircuitStatus::Active);
    // The table points at the committed file, not a copy of it.
    assert_eq!(key.vk_bytes(), DEMO_VK);
    assert_eq!(key.vk_bytes().len(), 59 * 32);
    // `keccak256(circuit.vk)`, derived by build.rs. This is the value
    // `cargo xtask l2 admit` printed for the root and `verify` reproduces.
    assert_eq!(
        alloy_primitives::hex::encode(key.vk_hash()),
        "4f1e294540876d22e858ef46f62918a46fed2913898cc5cbe097b8abe3921e21"
    );
    assert_eq!(L2_KEYS.len(), 1);
    assert_eq!(L2_KEYS[0].claim(), CLAIM);
}

#[test]
fn an_unregistered_pair_has_no_keys() {
    // Either side of the one registered chain, so a binary search that lands
    // on the wrong entry is caught rather than the empty case being trivial.
    assert!(l2_keys(57004, Claim::Tribute).is_empty());
    assert!(l2_keys(57006, Claim::Tribute).is_empty());
    assert!(l2_keys(1, Claim::Tribute).is_empty());
    // An unknown *claim* is unrepresentable while `Claim` has one variant;
    // the second claim to land here should add the symmetric assertion.
}

#[test]
fn the_key_header_gives_the_proof_length() {
    // log_n = 16 for this circuit: 82 + 12*16 proof words, four public words.
    assert_eq!(
        outbe_l2_zk_canonical::proof_words(DEMO_VK, PUBLIC_INPUT_COUNT).unwrap(),
        274
    );
    assert_eq!(combined_len(DEMO_VK, PUBLIC_INPUT_COUNT).unwrap(), 8900);
    // A key whose header declares a different public-input count is not this
    // claim's key, whatever the manifest says.
    assert!(matches!(combined_len(DEMO_VK, 5), Err(Error::Proof(_))));
    assert!(matches!(combined_len(&[0u8; 32], 4), Err(Error::Proof(_))));
}

#[test]
fn public_inputs_round_trip_through_the_decoder() {
    let public = sample();
    assert_eq!(
        public_words(&public),
        [
            public.owner,
            public.nft_hash,
            public.binding_hash,
            public.merkle_root
        ],
        "public_words must stay in claims/tribute/abi.json order"
    );
    let decoded = decode_public_inputs(&combined(&public, DEMO_VK), DEMO_VK).unwrap();
    assert_eq!(decoded, public);
}

#[test]
fn public_inputs_round_trip_through_the_alloy_mirror() {
    let public = sample();
    let ethereum = alloy::PublicInputs::try_from(public).unwrap();
    assert_eq!(ethereum.owner.as_slice()[31], 11);
    assert_eq!(PublicInputs::try_from(ethereum).unwrap(), public);
}

#[test]
fn the_decoder_rejects_a_wrong_public_input_count() {
    let mut proof = combined(&sample(), DEMO_VK);
    proof[..4].copy_from_slice(&3u32.to_be_bytes());
    assert!(matches!(
        decode_public_inputs(&proof, DEMO_VK),
        Err(Error::Proof(_))
    ));
}

#[test]
fn the_decoder_rejects_a_truncated_proof() {
    let proof = combined(&sample(), DEMO_VK);
    assert!(matches!(
        decode_public_inputs(&proof[..proof.len() - 32], DEMO_VK),
        Err(Error::Proof(_))
    ));
}

#[test]
fn the_decoder_rejects_a_non_canonical_field_word() {
    let mut proof = combined(&sample(), DEMO_VK);
    // The modulus itself: a 32-byte value that is not a field element. It must
    // be rejected, never silently reduced onto zero.
    proof[4..36].copy_from_slice(&FR_MODULUS);
    assert!(matches!(
        decode_public_inputs(&proof, DEMO_VK),
        Err(Error::NonCanonical("public input"))
    ));
}

#[test]
fn the_encoder_rejects_a_wrong_proof_length() {
    let words = public_words(&sample());
    assert!(matches!(
        encode_combined_proof(&words, &[vec![0u8; 32]], DEMO_VK),
        Err(Error::Proof(_))
    ));
    let mut proof = vec![[0u8; 32].to_vec(); 274];
    proof[0].pop();
    assert!(matches!(
        encode_combined_proof(&words, &proof, DEMO_VK),
        Err(Error::Proof(_))
    ));
}
