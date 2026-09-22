//! Barretenberg proving/verification cost across the canonical circuits.
//!
//! Measures the end-to-end backend cost a caller actually pays:
//! `generate` = ACVM solve + SRS load + bb prove; `verify` = bb verify. Covers
//! the ownership circuit (normal and low-memory mode) and the heavier Demo
//! Tribute proof. Run with `cargo bench -p outbe-zk-backend --features barretenberg`.

use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, Criterion};

use outbe_protocol::error::Error;
use outbe_protocol::primitive::signature::SignatureScheme;
use outbe_protocol::protocol::entity::{Entity, Owned};
use outbe_protocol::protocol::imt::Imt;
use outbe_protocol::protocol::key::{NftSecret, Signer};
use outbe_protocol::protocol::zk::{ProofGenerator, ProofVerifier};
use outbe_protocol::{OutbeV1, Suite};
use outbe_zk_backend::barretenberg::{Barretenberg, CANONICAL_SRS_POINTS};
use outbe_zk_canonical::demo_tribute::{demo_tribute_domain, DemoTributeProvable};
use outbe_zk_canonical::noir::demo_tribute::DemoTribute;
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

fn bench_proving(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    // bb's CRS is one-shot per process, so pre-size it to the canonical set's
    // largest circuit up front (ownership and the Demo Tribute proof both need a
    // 2^16 domain) — a smaller circuit proving first would fix the CRS too small.
    outbe_zk_backend::barretenberg::preinit_srs(CANONICAL_SRS_POINTS).expect("preinit SRS");

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

    // --- demo tribute proof (ownership + depth-32 Merkle inclusion) ---
    let (td, signer, binding) = sample(&mut rng);
    let tree = Imt::<OutbeV1>::new(demo_tribute_domain(), Fr::from(0u64), INCLUSION_DEPTH).unwrap();
    let path = tree.empty_inclusion_path(0);
    let (demo_w, demo_p) = td
        .derive_demo_tribute_witness(&mut rng, &signer, binding, &path)
        .unwrap();

    let mut g = c.benchmark_group("demo_tribute");
    g.sample_size(10);
    g.bench_function("prove", |b| {
        b.iter(|| {
            ProofGenerator::<OutbeV1, DemoTribute>::generate(
                &Barretenberg::default(),
                &demo_w,
                &demo_p,
            )
            .unwrap()
        })
    });
    let demo_proof = ProofGenerator::<OutbeV1, DemoTribute>::generate(
        &Barretenberg::default(),
        &demo_w,
        &demo_p,
    )
    .unwrap();
    // Warmup verify (also asserts validity) so the measurement excludes one-time cost.
    assert!(
        ProofVerifier::<OutbeV1, DemoTribute>::verify(
            &Barretenberg::default(),
            &demo_p,
            &demo_proof,
        )
        .unwrap(),
        "warmup verify must pass for demo tribute",
    );
    g.bench_function("verify", |b| {
        b.iter(|| {
            ProofVerifier::<OutbeV1, DemoTribute>::verify(
                &Barretenberg::default(),
                &demo_p,
                &demo_proof,
            )
            .unwrap()
        })
    });
    g.finish();
}

criterion_group!(benches, bench_proving);
criterion_main!(benches);
