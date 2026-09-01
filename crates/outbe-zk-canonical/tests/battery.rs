#![allow(clippy::doc_lazy_continuation)]
//! The ZK-canonical half of the protocol battery, run against the
//! production suite. Exercises the build-generated noir circuit types
//! (`OwnershipProof` / `FlatAggregationN*` and their `Witness` /
//! `PublicInputs`) through the core ZK seams, on `OutbeV1`. The generated
//! circuits are BN254-specific, so this battery is concrete to `OutbeV1`
//! (cross-suite pluggability is the core battery's job).
//!
//! The concrete entity types live in consumer crates, so the battery
//! carries its own minimal entity (`TestNft`).

use ark_ff::PrimeField;
use ark_ff::Zero;
use ark_std::rand::Rng;
use ark_std::UniformRand;

use outbe_protocol::error::Error;
use outbe_protocol::primitive::signature::SignatureScheme;
use outbe_protocol::protocol::entity::{Entity, Owned};
use outbe_protocol::protocol::key::{NftSecret, Signer};
use outbe_protocol::protocol::zk::{Circuit, ProofGenerator, ProofVerifier};
use outbe_protocol::{OutbeV1, Suite};

use outbe_protocol::protocol::imt::Imt;
use outbe_zk_canonical::aggregation::{AggregationTier, AnyTier, FlatAggregation, Slot};
use outbe_zk_canonical::full::{full_circuit_domain, FullProvable};
use outbe_zk_canonical::noir::flat_aggregation_n4::FlatAggregationN4;
use outbe_zk_canonical::noir::flat_aggregation_n64::FlatAggregationN64;
use outbe_zk_canonical::noir::full_proof::FullProof;
use outbe_zk_canonical::noir::ownership_proof::{OwnershipProof, PublicInputs, Witness};
use outbe_zk_canonical::ownership::{verify_signature, Provable};
use outbe_zk_canonical::CircuitId;

type Fr = <OutbeV1 as Suite>::Field;

/// Minimal owned entity for exercising the protocol: a stored id seed and a
/// flat body. The real entity types live in `outbe-integration`.
struct TestNft {
    id: Fr,
    owner: Fr,
    fields: Vec<Fr>,
}

impl Entity<OutbeV1> for TestNft {
    fn id_seed(&self) -> Result<Fr, Error> {
        Ok(self.id)
    }
    fn encode_id_body(&self, _out: &mut Vec<Fr>) -> Result<(), Error> {
        Ok(())
    }
    fn encode_body(&self, out: &mut Vec<Fr>) -> Result<(), Error> {
        out.extend_from_slice(&self.fields);
        Ok(())
    }
}
impl Owned<OutbeV1> for TestNft {
    fn owner(&self) -> Result<Fr, Error> {
        Ok(self.owner)
    }
}

/// One mock backend implementing BOTH proof traits for the ownership and
/// aggregation circuits: the "proof" is the circuit's public-input field
/// vector echoed back. Exercises the generate→verify round-trip and the
/// `V::Proof = G::Proof` constraint.
struct MockBackend;

impl ProofGenerator<OutbeV1, OwnershipProof> for MockBackend {
    type Proof = Vec<Fr>;
    fn generate(&self, _witness: &Witness, public: &PublicInputs) -> Result<Self::Proof, Error> {
        Ok(<OwnershipProof as Circuit<OutbeV1>>::public_inputs(public))
    }
}
impl ProofVerifier<OutbeV1, OwnershipProof> for MockBackend {
    type Proof = Vec<Fr>;
    fn verify(&self, public: &PublicInputs, proof: &Self::Proof) -> Result<bool, Error> {
        Ok(<OwnershipProof as Circuit<OutbeV1>>::public_inputs(public) == *proof)
    }
}

impl ProofGenerator<OutbeV1, FlatAggregationN4> for MockBackend {
    type Proof = Vec<Fr>;
    fn generate(
        &self,
        _witness: &<FlatAggregationN4 as Circuit<OutbeV1>>::Witness,
        public: &<FlatAggregationN4 as Circuit<OutbeV1>>::PublicInputs,
    ) -> Result<Self::Proof, Error> {
        Ok(<FlatAggregationN4 as Circuit<OutbeV1>>::public_inputs(
            public,
        ))
    }
}
impl ProofVerifier<OutbeV1, FlatAggregationN4> for MockBackend {
    type Proof = Vec<Fr>;
    fn verify(
        &self,
        public: &<FlatAggregationN4 as Circuit<OutbeV1>>::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool, Error> {
        Ok(<FlatAggregationN4 as Circuit<OutbeV1>>::public_inputs(public) == *proof)
    }
}

impl ProofGenerator<OutbeV1, FlatAggregationN64> for MockBackend {
    type Proof = Vec<Fr>;
    fn generate(
        &self,
        _witness: &<FlatAggregationN64 as Circuit<OutbeV1>>::Witness,
        public: &<FlatAggregationN64 as Circuit<OutbeV1>>::PublicInputs,
    ) -> Result<Self::Proof, Error> {
        Ok(<FlatAggregationN64 as Circuit<OutbeV1>>::public_inputs(
            public,
        ))
    }
}
impl ProofVerifier<OutbeV1, FlatAggregationN64> for MockBackend {
    type Proof = Vec<Fr>;
    fn verify(
        &self,
        public: &<FlatAggregationN64 as Circuit<OutbeV1>>::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool, Error> {
        Ok(<FlatAggregationN64 as Circuit<OutbeV1>>::public_inputs(public) == *proof)
    }
}

impl ProofGenerator<OutbeV1, FullProof> for MockBackend {
    type Proof = Vec<Fr>;
    fn generate(
        &self,
        _witness: &<FullProof as Circuit<OutbeV1>>::Witness,
        public: &<FullProof as Circuit<OutbeV1>>::PublicInputs,
    ) -> Result<Self::Proof, Error> {
        Ok(<FullProof as Circuit<OutbeV1>>::public_inputs(public))
    }
}
impl ProofVerifier<OutbeV1, FullProof> for MockBackend {
    type Proof = Vec<Fr>;
    fn verify(
        &self,
        public: &<FullProof as Circuit<OutbeV1>>::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool, Error> {
        Ok(<FullProof as Circuit<OutbeV1>>::public_inputs(public) == *proof)
    }
}

/// Run the mock generate→verify round-trip for circuit `C`, returning whether
/// the proof verifies. `C` is named explicitly because `MockBackend` serves
/// several circuits, so it can't be inferred from the witness / public-input
/// types — this keeps the call sites to a single turbofish.
fn mock_round_trip<C>(witness: &C::Witness, public: &C::PublicInputs) -> bool
where
    C: Circuit<OutbeV1>,
    MockBackend:
        ProofGenerator<OutbeV1, C, Proof = Vec<Fr>> + ProofVerifier<OutbeV1, C, Proof = Vec<Fr>>,
{
    let proof = MockBackend.generate(witness, public).unwrap();
    MockBackend.verify(public, &proof).unwrap()
}

fn sample_body<R: Rng>(rng: &mut R) -> Vec<Fr> {
    vec![
        Fr::from(978u64),   // currency
        Fr::from(1_000u64), // base
        Fr::from(42u64),    // atto
        Fr::rand(rng),      // suId
        Fr::rand(rng),      // suId
    ]
}

fn sample_nft<R: Rng>(rng: &mut R, owner: Fr) -> TestNft {
    TestNft {
        id: owner,
        owner,
        fields: sample_body(rng),
    }
}

#[test]
fn outbe_suite() {
    let mut rng = ark_std::test_rng();

    let (sk, pk) = <OutbeV1 as Suite>::Signature::keypair(&mut rng);
    let nonce = Fr::rand(&mut rng);
    let owner = OutbeV1::derive_owner(&pk, nonce).unwrap();
    let binding = OutbeV1::binding(&[7u8; 20], &[9u8; 32], 1234).unwrap();
    let td = sample_nft(&mut rng, owner);

    // Canonical descriptor identity is carried on the marker types.
    assert_eq!(OwnershipProof::LABEL, "outbe.ownership");
    assert_eq!(OwnershipProof::VERSION, "1.0.0");
    assert!(!OwnershipProof::BYTECODE_B64.is_empty());
    assert_ne!(OwnershipProof::CIRCUIT_HASH, [0u8; 32]);
    assert!(!OwnershipProof::VK_BYTES.is_empty());
    assert_ne!(OwnershipProof::VK_HASH, [0u8; 32]);

    // --- ownership proof: round-trips; tamper fails; bad owner rejected ---
    let signer = Signer::from_secret(NftSecret::new(sk), nonce).unwrap();
    let (witness, public) = td
        .derive_ownership_witness(&mut rng, &signer, binding)
        .unwrap();
    // Re-derive the signature from the signer to run the in-protocol check
    // (the witness packs the signature one-way for the circuit).
    let signature = <OutbeV1 as Suite>::Signature::sign(
        &mut rng,
        &sk,
        OutbeV1::signing_payload(public.nft_hash, witness.nonce, public.binding_hash).unwrap(),
    )
    .unwrap();
    assert!(
        verify_signature::<OutbeV1>(&public, witness.nonce, &pk, &signature).unwrap(),
        "valid ownership failed to verify"
    );

    // full round-trip through the ZK seams (mock backends, shared Proof type)
    assert!(
        td.prove_and_verify(&mut rng, &signer, binding, &MockBackend, &MockBackend)
            .unwrap(),
        "prove_and_verify round-trip failed"
    );

    // tampered nonce -> different payload -> signature no longer verifies
    let bad_nonce = witness.nonce + Fr::from(1u64);
    assert!(
        !verify_signature::<OutbeV1>(&public, bad_nonce, &pk, &signature).unwrap(),
        "tampered ownership verified"
    );

    // entity whose stored owner doesn't match (pk, nonce) must be rejected
    let bad_owner = Fr::rand(&mut rng);
    let bad_td = TestNft {
        id: bad_owner,
        owner: bad_owner,
        fields: sample_body(&mut rng),
    };
    assert!(
        bad_td
            .derive_ownership_witness(&mut rng, &signer, binding)
            .is_err(),
        "owner mismatch was not rejected"
    );

    // --- aggregation: pad 3 reals to the generated tier-4 circuit ---
    let mut reals: Vec<Slot> = Vec::new();
    for _ in 0..3 {
        let (s_i, p_i) = <OutbeV1 as Suite>::Signature::keypair(&mut rng);
        let n_i = Fr::rand(&mut rng);
        let o_i = OutbeV1::derive_owner(&p_i, n_i).unwrap();
        let td_i = sample_nft(&mut rng, o_i);
        let signer_i = Signer::from_secret(NftSecret::new(s_i), n_i).unwrap();
        reals.push(
            td_i.derive_ownership_witness(&mut rng, &signer_i, binding)
                .unwrap(),
        );
    }
    // FlatAggregationN4::assemble pads to tier 4 and builds the generated
    // FlatAggregationN4 (Witness, PublicInputs) pair.
    let (agg_witness, agg_public) =
        <FlatAggregationN4 as FlatAggregation<OutbeV1>>::assemble(&mut rng, reals, binding)
            .unwrap();
    let pubs = &agg_public.public_inputs;
    assert_eq!(pubs.len(), 2 * 4 + 1, "wrong public-input arity");
    assert_eq!(*pubs.last().unwrap(), binding, "binding not last");
    // Padded slot (index 3) is distinguished by nft_hash == 0, NOT a zeroed
    // owner: the circuit enforces `owner == Poseidon3(pk, nonce)` for every
    // slot, so the padding owner must be the real derived value (non-zero).
    assert_eq!(pubs[2 * 3 + 1], Fr::zero(), "padded nft_hash should be 0");
    assert_ne!(
        pubs[2 * 3],
        Fr::zero(),
        "padded owner must be the real derived owner"
    );
    // generated witness carries N=4 slots
    assert_eq!(agg_witness.nonce.len(), 4, "did not pad to tier");

    // Runtime tier selection picks the exact circuit for the count.
    assert_eq!(AggregationTier::for_count(3), Some(AggregationTier::N4));
    assert_eq!(AggregationTier::N4.capacity(), 4);
    assert_eq!(AggregationTier::N4.label(), "outbe.flat_aggregation.n4");

    // round-trip through the seams
    assert!(mock_round_trip::<FlatAggregationN4>(
        &agg_witness,
        &agg_public
    ));
}

/// The largest tier (N=64) assembles and round-trips through the seams,
/// padding a partial batch up to capacity. Drives both the typed
/// (`FlatAggregationN64::assemble`) and the runtime-dispatch
/// (`AggregationTier`) paths.
#[test]
fn flat_aggregation_n64_round_trip() {
    let mut rng = ark_std::test_rng();
    let binding = OutbeV1::binding(&[3u8; 20], &[5u8; 32], 777).unwrap();

    // 50 real slots → tier 64 (the smallest tier that fits).
    const REAL: usize = 50;
    assert_eq!(AggregationTier::for_count(REAL), Some(AggregationTier::N64));
    assert_eq!(AggregationTier::N64.capacity(), 64);
    assert_eq!(AggregationTier::N64.label(), "outbe.flat_aggregation.n64");

    let build_reals = |rng: &mut _| -> Vec<Slot> {
        (0..REAL)
            .map(|_| {
                let (s_i, p_i) = <OutbeV1 as Suite>::Signature::keypair(rng);
                let n_i = Fr::rand(rng);
                let o_i = OutbeV1::derive_owner(&p_i, n_i).unwrap();
                let td_i = sample_nft(rng, o_i);
                let signer_i = Signer::from_secret(NftSecret::new(s_i), n_i).unwrap();
                td_i.derive_ownership_witness(rng, &signer_i, binding)
                    .unwrap()
            })
            .collect()
    };

    // Typed path: FlatAggregationN64::assemble.
    let reals = build_reals(&mut rng);
    let (witness, public) =
        <FlatAggregationN64 as FlatAggregation<OutbeV1>>::assemble(&mut rng, reals, binding)
            .unwrap();
    assert_eq!(witness.pk.len(), 64, "witness padded to N=64");
    assert_eq!(witness.signature.len(), 64);
    assert_eq!(witness.nonce.len(), 64);
    assert_eq!(public.public_inputs.len(), 2 * 64 + 1, "2N+1 public inputs");
    assert_eq!(
        *public.public_inputs.last().unwrap(),
        binding,
        "binding is last"
    );
    // Every padded slot (indices REAL..64) has nft_hash == 0 but a non-zero
    // (real, derived) owner, as the circuit's per-slot constraint requires.
    for i in REAL..64 {
        assert_eq!(
            public.public_inputs[2 * i + 1],
            Fr::zero(),
            "padded nft_hash != 0"
        );
        assert_ne!(
            public.public_inputs[2 * i],
            Fr::zero(),
            "padded owner zeroed"
        );
    }

    // Round-trip through the ZK seams.
    assert!(
        mock_round_trip::<FlatAggregationN64>(&witness, &public),
        "n64 proof did not verify"
    );

    // Runtime-dispatch path: AggregationTier::assemble → AnyTier::N64, and its
    // public inputs round-trip identically.
    let tier = AggregationTier::for_count(REAL).unwrap();
    let reals = build_reals(&mut rng);
    match tier
        .assemble::<OutbeV1, _>(&mut rng, reals, binding)
        .unwrap()
    {
        AnyTier::N64(w, p) => {
            assert_eq!(w.nonce.len(), 64);
            assert_eq!(p.public_inputs.len(), 2 * 64 + 1);
            assert!(mock_round_trip::<FlatAggregationN64>(&w, &p));
        }
        _ => panic!("for_count(50) should select the N64 tier"),
    }

    // Capacity overflow is rejected.
    let too_many: Vec<Slot> = build_reals(&mut rng); // 50 — fits; push past 64
    let overflow = {
        let mut v = too_many;
        while v.len() <= 64 {
            v.push(
                <FlatAggregationN64 as FlatAggregation<OutbeV1>>::padding_slot(&mut rng, binding)
                    .unwrap(),
            );
        }
        v
    };
    assert!(
        <FlatAggregationN64 as FlatAggregation<OutbeV1>>::assemble(&mut rng, overflow, binding)
            .is_err(),
        "exceeding tier capacity must error"
    );
}

/// Full proof = §4.2 ownership + depth-32 Merkle inclusion of `nft_hash`.
#[test]
fn full_proof_round_trip() {
    let mut rng = ark_std::test_rng();
    let (sk, pk) = <OutbeV1 as Suite>::Signature::keypair(&mut rng);
    let nonce = Fr::rand(&mut rng);
    let owner = OutbeV1::derive_owner(&pk, nonce).unwrap();
    let binding = OutbeV1::binding(&[3u8; 20], &[4u8; 32], 99).unwrap();
    let td = sample_nft(&mut rng, owner);
    let signer = Signer::from_secret(NftSecret::new(sk), nonce).unwrap();

    // Inclusion: place nft_hash at index 0 of an otherwise-empty depth-32 tree.
    let tree =
        Imt::<OutbeV1>::new(full_circuit_domain(), outbe_zk_canonical::INCLUSION_DEPTH).unwrap();
    let path = tree.empty_inclusion_path(0);
    let (witness, public) = td
        .derive_full_witness(&mut rng, &signer, binding, &path)
        .unwrap();

    assert_eq!(public.owner, owner);
    assert_eq!(public.binding_hash, binding);
    assert_eq!(witness.merkle_path_siblings.len(), 32);
    // Index 0 => current-left at every level => all path bits are true.
    assert_eq!(witness.merkle_path_indices, [true; 32]);
    // The public root is the inclusion path resolved over nft_hash (the leaf).
    assert_eq!(
        public.expected_merkle_root,
        path.root(public.nft_hash).unwrap(),
        "merkle root mismatch"
    );

    // Round-trip through the seams.
    assert!(mock_round_trip::<FullProof>(&witness, &public));
}

/// The prove-side `witness_inputs` flatten is in ACIR witness-index order and
/// stays locked to the ABI: ownership = `pk`(2) + `signature`(64) + `nonce`(1)
/// + 3 public = 70 leaves, the byte array expands one witness per byte, and the
/// public tail is exactly the verify-side `public_inputs` projection — so
/// the prover (integration) and verifier (chain) read one consistent mapping.
#[test]
fn witness_inputs_layout_is_canonical() {
    let mut rng = ark_std::test_rng();
    let (sk, pk) = <OutbeV1 as Suite>::Signature::keypair(&mut rng);
    let nonce = Fr::rand(&mut rng);
    let owner = OutbeV1::derive_owner(&pk, nonce).unwrap();
    let binding = OutbeV1::binding(&[1u8; 20], &[2u8; 32], 7).unwrap();
    let td = sample_nft(&mut rng, owner);
    let signer = Signer::from_secret(NftSecret::new(sk), nonce).unwrap();
    let (witness, public) = td
        .derive_ownership_witness(&mut rng, &signer, binding)
        .unwrap();

    let w = <OwnershipProof as Circuit<OutbeV1>>::witness_inputs(&witness, &public);
    // pk.x, pk.y, signature[0..64], nonce, owner, nft_hash, binding_hash.
    assert_eq!(w.len(), 2 + 64 + 1 + 3, "ownership witness arity");

    let (x, y) =
        outbe_protocol::primitive::curve::coords::<<OutbeV1 as Suite>::Curve>(&pk).unwrap();
    assert_eq!(w[0], x, "Witness(0) = pk.x");
    assert_eq!(w[1], y, "Witness(1) = pk.y");
    // Each signature byte is its own witness (index 2..66).
    assert_eq!(
        w[2],
        Fr::from(witness.signature[0] as u64),
        "Witness(2) = signature[0]"
    );
    assert_eq!(
        w[65],
        Fr::from(witness.signature[63] as u64),
        "Witness(65) = signature[63]"
    );
    assert_eq!(w[66], witness.nonce, "Witness(66) = nonce");

    // The public tail equals the verify-side projection, in the same order.
    let public_fields = <OwnershipProof as Circuit<OutbeV1>>::public_inputs(&public);
    assert_eq!(
        &w[67..],
        public_fields.as_slice(),
        "public tail == public_inputs"
    );
}

/// The Emit mint statement carries 8 public field elements: `chain_id`, two
/// field scalars, the owner address as one `EthAddress`-packed field, the
/// three 120-bit `U256` limbs of `mint_units`, and the change commitment.
#[test]
fn emit_mint_descriptor_and_abi_layout() {
    use alloy_primitives::U256;
    use outbe_zk_canonical::noir::emit_mint as emit;
    use outbe_zk_canonical::u256;

    assert_eq!(emit::EmitMint::LABEL, "outbe.emit.mint");
    assert_eq!(emit::EmitMint::VERSION, "1.5.0");
    assert!(!emit::EmitMint::BYTECODE_B64.is_empty());
    assert_ne!(emit::EmitMint::CIRCUIT_HASH, [0u8; 32]);
    assert!(!emit::EmitMint::VK_BYTES.is_empty());
    assert_ne!(emit::EmitMint::VK_HASH, [0u8; 32]);

    // Above the old u128 ceiling, so the upper limbs must carry value.
    let public_amount = (U256::from(0xfu64) << 128) + U256::from((1u128 << 100) + 40);
    let private_amount = public_amount + U256::from(60);
    let public_limbs = u256::to_limbs(public_amount);
    let private_limbs = u256::to_limbs(private_amount);
    let public = emit::PublicInputs {
        chain_id: 1,
        root: Fr::from(2u64),
        nullifier: Fr::from(3u64),
        note_owner: Fr::from_be_bytes_mod_order(&[0x22; 20]),
        mint_units: public_limbs,
        change_commitment: Fr::from(4u64),
    };
    let flat = <emit::EmitMint as Circuit<OutbeV1>>::public_inputs(&public);
    assert_eq!(flat.len(), 8, "Emit mint public-input arity");
    assert_eq!(
        &flat[..3],
        &[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]
    );
    assert_eq!(
        flat[3],
        Fr::from_be_bytes_mod_order(&[0x22; 20]),
        "note_owner is one big-endian-packed field, not 20 byte leaves"
    );
    assert_eq!(
        &flat[4..7],
        public_limbs.map(Fr::from).as_slice(),
        "u256 mint_units follows note_owner as three little-endian 120-bit limbs"
    );
    assert_eq!(flat[7], Fr::from(4u64), "change_commitment is last");

    let witness = emit::Witness {
        note_amount: private_limbs,
        note_spend_key: Fr::from(5u64),
        leaf_index: 1,
        auth_path: [Fr::from(7u64); 32],
    };
    let all = <emit::EmitMint as Circuit<OutbeV1>>::witness_inputs(&witness, &public);
    assert_eq!(all.len(), 45, "8 public + 37 private ABI leaves");
    assert_eq!(
        &all[..8],
        flat.as_slice(),
        "public inputs are the ABI prefix"
    );
    assert_eq!(
        &all[8..11],
        private_limbs.map(Fr::from).as_slice(),
        "u256 note_amount is encoded as three limbs without truncation"
    );
    assert_eq!(all[11], Fr::from(5u64), "note_spend_key");
    assert_eq!(all[12], Fr::from(1u64), "leaf_index");
    assert_eq!(&all[13..], &[Fr::from(7u64); 32], "auth_path");

    assert!(
        outbe_zk_canonical::noir::CIRCUIT_REGISTRY
            .iter()
            .any(|e| e.label == "outbe.emit.mint"),
        "Emit mint missing from CIRCUIT_REGISTRY"
    );
    assert!(
        outbe_zk_canonical::noir::CIRCUIT_REGISTRY
            .iter()
            .all(|e| e.label != "outbe.commitment_nullifier"),
        "revoked commitment-nullifier must not remain in CIRCUIT_REGISTRY"
    );
}

/// Paynote's descriptor and ABI layout. Mirrors the Emit mint case: the two
/// addresses cross as `EthAddress` newtypes, so each is a single packed field
/// rather than 20 byte leaves.
#[test]
fn paynote_descriptor_and_abi_layout() {
    use outbe_zk_canonical::noir::paynote as pay;

    assert_eq!(pay::Paynote::LABEL, "outbe.paynote");
    assert_eq!(pay::Paynote::VERSION, "1.0.0");
    assert!(!pay::Paynote::BYTECODE_B64.is_empty());
    assert_ne!(pay::Paynote::CIRCUIT_HASH, [0u8; 32]);
    assert!(!pay::Paynote::VK_BYTES.is_empty());
    assert_ne!(pay::Paynote::VK_HASH, [0u8; 32]);

    let asset = Fr::from_be_bytes_mod_order(&[0xa0; 20]);
    let spender = Fr::from_be_bytes_mod_order(&[0x33; 20]);
    let spend_amount = (1u128 << 100) + 40;
    let note_amount = spend_amount + 60;
    let public = pay::PublicInputs {
        chain_id: 1,
        root: Fr::from(2u64),
        nullifier: Fr::from(3u64),
        asset,
        spender,
        spend_amount,
        change_commitment: Fr::from(4u64),
    };
    let flat = <pay::Paynote as Circuit<OutbeV1>>::public_inputs(&public);
    assert_eq!(flat.len(), 7, "Paynote public-input arity");
    assert_eq!(
        &flat[..3],
        &[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]
    );
    assert_eq!(
        flat[3], asset,
        "asset is one big-endian-packed field, not 20 byte leaves"
    );
    assert_eq!(flat[4], spender, "spender likewise");
    assert_eq!(
        flat[5],
        Fr::from(spend_amount),
        "u128 spend_amount follows spender without truncation"
    );
    assert_eq!(flat[6], Fr::from(4u64), "change_commitment is last");

    let witness = pay::Witness {
        note_amount,
        note_spend_key: Fr::from(5u64),
        leaf_index: 1,
        auth_path: [Fr::from(7u64); 32],
    };
    let all = <pay::Paynote as Circuit<OutbeV1>>::witness_inputs(&witness, &public);
    assert_eq!(all.len(), 42, "7 public + 35 private ABI leaves");
    assert_eq!(
        &all[..7],
        flat.as_slice(),
        "public inputs are the ABI prefix"
    );
    assert_eq!(
        all[7],
        Fr::from(note_amount),
        "u128 note_amount is encoded without truncation"
    );
    assert_eq!(all[8], Fr::from(5u64), "note_spend_key");
    assert_eq!(all[9], Fr::from(1u64), "leaf_index");
    assert_eq!(&all[10..], &[Fr::from(7u64); 32], "auth_path");

    assert!(
        outbe_zk_canonical::noir::CIRCUIT_REGISTRY
            .iter()
            .any(|e| e.label == "outbe.paynote"),
        "Paynote missing from CIRCUIT_REGISTRY"
    );
}
