//! Barretenberg proving/verification cost across the canonical circuits.
//!
//! Measures the end-to-end backend cost a caller actually pays:
//! `generate` = ACVM solve + SRS load + bb prove; `verify` = bb verify. Covers
//! the ownership circuit (normal and low-memory mode) and the heavier full
//! proof. Run with `cargo bench -p outbe-zk-backend --features barretenberg`.

use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, Criterion};

use outbe_protocol::error::Error;
use outbe_protocol::primitive::signature::SignatureScheme;
use outbe_protocol::protocol::entity::{Entity, Owned};
use outbe_protocol::protocol::imt::Imt;
use outbe_protocol::protocol::key::{NftSecret, Signer};
use outbe_protocol::protocol::zk::{ProofGenerator, ProofVerifier};
use outbe_protocol::{OutbeV1, Suite};
use outbe_zk_backend::barretenberg::Barretenberg;
use outbe_zk_canonical::aggregation::{FlatAggregation, Slot};
use outbe_zk_canonical::full::{full_circuit_domain, FullProvable};
use outbe_zk_canonical::noir::flat_aggregation_n1::FlatAggregationN1;
use outbe_zk_canonical::noir::flat_aggregation_n16::FlatAggregationN16;
use outbe_zk_canonical::noir::flat_aggregation_n2::FlatAggregationN2;
use outbe_zk_canonical::noir::flat_aggregation_n32::FlatAggregationN32;
use outbe_zk_canonical::noir::flat_aggregation_n4::FlatAggregationN4;
use outbe_zk_canonical::noir::flat_aggregation_n64::FlatAggregationN64;
use outbe_zk_canonical::noir::flat_aggregation_n8::FlatAggregationN8;
use outbe_zk_canonical::noir::full_proof::FullProof;
use outbe_zk_canonical::noir::ownership_proof::OwnershipProof;
use outbe_zk_canonical::ownership::Provable;
use outbe_zk_canonical::INCLUSION_DEPTH;

type Fr = <OutbeV1 as Suite>::Field;

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

fn sample(rng: &mut impl ark_std::rand::Rng) -> (TestNft, Signer<OutbeV1>, Fr) {
    let (sk, pk) = <OutbeV1 as Suite>::Signature::keypair(rng);
    let nonce = Fr::rand(rng);
    let owner = OutbeV1::derive_owner(&pk, nonce).unwrap();
    let binding = Fr::from(7u64);
    let td = TestNft {
        id: owner,
        owner,
        fields: vec![Fr::from(978u64), Fr::from(100u64)],
    };
    let signer = Signer::from_secret(NftSecret::new(sk), nonce).unwrap();
    (td, signer, binding)
}

/// `n` real ownership slots (each its own key/owner), to fill an aggregation
/// tier before padding.
fn build_reals(rng: &mut impl ark_std::rand::Rng, n: usize, binding: Fr) -> Vec<Slot> {
    (0..n)
        .map(|_| {
            let (sk, pk) = <OutbeV1 as Suite>::Signature::keypair(rng);
            let nonce = Fr::rand(rng);
            let owner = OutbeV1::derive_owner(&pk, nonce).unwrap();
            let td = TestNft {
                id: owner,
                owner,
                fields: vec![Fr::from(978u64)],
            };
            let signer = Signer::from_secret(NftSecret::new(sk), nonce).unwrap();
            td.derive_ownership_witness(rng, &signer, binding).unwrap()
        })
        .collect()
}

/// Assemble each tier at full capacity and bench its prove **and** verify. The
/// verify input is proven once up front, then a warmup verify runs (also
/// asserting the proof is valid) so the timed measurement excludes any one-time
/// VK/setup cost.
macro_rules! bench_tiers {
    ($g:expr, $rng:expr, $binding:expr; $( $marker:ty => ($n:expr, $label:literal) ),+ $(,)?) => {
        $({
            let reals = build_reals(&mut $rng, $n, $binding);
            let (w, p) = <$marker as FlatAggregation<OutbeV1>>::assemble(&mut $rng, reals, $binding).unwrap();
            $g.bench_function(concat!($label, "/prove"), |b| {
                b.iter(|| {
                    ProofGenerator::<OutbeV1, $marker>::generate(&Barretenberg::default(), &w, &p).unwrap()
                })
            });
            // Verify: prove once for the input, warm up (and assert validity),
            // then measure.
            let proof = ProofGenerator::<OutbeV1, $marker>::generate(&Barretenberg::default(), &w, &p).unwrap();
            assert!(
                ProofVerifier::<OutbeV1, $marker>::verify(&Barretenberg::default(), &p, &proof).unwrap(),
                concat!("warmup verify must pass for ", $label),
            );
            $g.bench_function(concat!($label, "/verify"), |b| {
                b.iter(|| {
                    ProofVerifier::<OutbeV1, $marker>::verify(&Barretenberg::default(), &p, &proof).unwrap()
                })
            });
        })+
    };
}

fn bench_proving(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    // bb's CRS is one-shot per process, and this bench proves circuits of many
    // sizes — so pre-size it to the largest (n64 = 2^19 domain under Poseidon2)
    // up front, or the first (smaller) prove would fix the CRS too small for n64.
    outbe_zk_backend::barretenberg::preinit_srs((1 << 19) + 1).expect("preinit SRS");

    // --- ownership ---
    let (td, signer, binding) = sample(&mut rng);
    let (own_w, own_p) = td
        .derive_ownership_witness(&mut rng, &signer, binding)
        .unwrap();

    let mut g = c.benchmark_group("ownership");
    g.sample_size(10);
    g.bench_function("prove", |b| {
        b.iter(|| {
            ProofGenerator::<OutbeV1, OwnershipProof>::generate(
                &Barretenberg::default(),
                &own_w,
                &own_p,
            )
            .unwrap()
        })
    });
    g.bench_function("prove_low_memory", |b| {
        let backend = Barretenberg {
            disable_zk: true,
            low_memory: true,
            max_storage_usage: None,
        };
        b.iter(|| {
            ProofGenerator::<OutbeV1, OwnershipProof>::generate(&backend, &own_w, &own_p).unwrap()
        })
    });
    let own_proof = ProofGenerator::<OutbeV1, OwnershipProof>::generate(
        &Barretenberg::default(),
        &own_w,
        &own_p,
    )
    .unwrap();
    // Warmup verify (also asserts validity) so the measurement excludes one-time cost.
    assert!(
        ProofVerifier::<OutbeV1, OwnershipProof>::verify(
            &Barretenberg::default(),
            &own_p,
            &own_proof
        )
        .unwrap(),
        "warmup verify must pass for ownership",
    );
    g.bench_function("verify", |b| {
        b.iter(|| {
            ProofVerifier::<OutbeV1, OwnershipProof>::verify(
                &Barretenberg::default(),
                &own_p,
                &own_proof,
            )
            .unwrap()
        })
    });
    g.finish();

    // --- full proof (ownership + depth-32 Merkle inclusion) ---
    let (td, signer, binding) = sample(&mut rng);
    let tree = Imt::<OutbeV1>::new(full_circuit_domain(), INCLUSION_DEPTH).unwrap();
    let path = tree.empty_inclusion_path(0);
    let (full_w, full_p) = td
        .derive_full_witness(&mut rng, &signer, binding, &path)
        .unwrap();

    let mut g = c.benchmark_group("full");
    g.sample_size(10);
    g.bench_function("prove", |b| {
        b.iter(|| {
            ProofGenerator::<OutbeV1, FullProof>::generate(
                &Barretenberg::default(),
                &full_w,
                &full_p,
            )
            .unwrap()
        })
    });
    let full_proof =
        ProofGenerator::<OutbeV1, FullProof>::generate(&Barretenberg::default(), &full_w, &full_p)
            .unwrap();
    // Warmup verify (also asserts validity) so the measurement excludes one-time cost.
    assert!(
        ProofVerifier::<OutbeV1, FullProof>::verify(&Barretenberg::default(), &full_p, &full_proof)
            .unwrap(),
        "warmup verify must pass for full",
    );
    g.bench_function("verify", |b| {
        b.iter(|| {
            ProofVerifier::<OutbeV1, FullProof>::verify(
                &Barretenberg::default(),
                &full_p,
                &full_proof,
            )
            .unwrap()
        })
    });
    g.finish();

    // --- aggregation tiers n1..n64 (each filled to capacity, then proven) ---
    let binding = Fr::from(9u64);
    let mut g = c.benchmark_group("aggregation");
    g.sample_size(10);
    bench_tiers!(g, rng, binding;
        FlatAggregationN1 => (1, "n1"),
        FlatAggregationN2 => (2, "n2"),
        FlatAggregationN4 => (4, "n4"),
        FlatAggregationN8 => (8, "n8"),
        FlatAggregationN16 => (16, "n16"),
        FlatAggregationN32 => (32, "n32"),
        FlatAggregationN64 => (64, "n64"),
    );
    g.finish();
}

criterion_group!(benches, bench_proving);
criterion_main!(benches);
