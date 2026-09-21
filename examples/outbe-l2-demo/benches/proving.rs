//! Barretenberg proving/verification cost for the registered tribute root.
//!
//! Measures what a caller actually pays: `generate` = ACVM solve + SRS load +
//! bb prove; `verify` = bb verify. Run with
//! `cargo bench -p outbe-l2-demo`.

use criterion::{criterion_group, criterion_main, Criterion};

use outbe_l2_demo::{empty_tree, prove_tribute, TributeDemo};
use outbe_zk_backend::barretenberg::Barretenberg;
use outbe_zk_core::zk::{ProofGenerator, ProofVerifier};

/// The same draft every test starts from — benched, so the measured witness is
/// the one under test rather than a hand-built copy of it.
#[path = "../tests/common/mod.rs"]
mod common;

fn bench_proving(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    // bb's CRS is one-shot per process, so pre-size it up front; a first,
    // smaller prove would fix it too small. One dyadic tier of headroom over
    // this circuit's own 2^16 domain — the same size `srs_pins.rs` prints and
    // `PINNED_G1_SHA256` pins.
    outbe_zk_backend::barretenberg::preinit_srs((1 << 17) + 1).expect("preinit SRS");

    let f = common::fixture(&mut rng);
    let tree = empty_tree().unwrap();
    let path = tree.empty_inclusion_path(0);
    let (w, p) = prove_tribute(&mut rng, &f.claim, &f.signer, f.binding, &path).unwrap();

    let mut g = c.benchmark_group("tribute");
    g.sample_size(10);
    g.bench_function("prove", |b| {
        b.iter(|| {
            ProofGenerator::<TributeDemo>::generate(&Barretenberg::default(), &w, &p).unwrap()
        })
    });
    g.bench_function("prove_low_memory", |b| {
        let backend = Barretenberg {
            disable_zk: true,
            low_memory: true,
            max_storage_usage: None,
        };
        b.iter(|| ProofGenerator::<TributeDemo>::generate(&backend, &w, &p).unwrap())
    });
    let proof = ProofGenerator::<TributeDemo>::generate(&Barretenberg::default(), &w, &p).unwrap();
    // Warmup verify (also asserts validity) so the measurement excludes one-time cost.
    assert!(
        ProofVerifier::<TributeDemo>::verify(&Barretenberg::default(), &p, &proof).unwrap(),
        "warmup verify must pass",
    );
    g.bench_function("verify", |b| {
        b.iter(|| {
            ProofVerifier::<TributeDemo>::verify(&Barretenberg::default(), &p, &proof).unwrap()
        })
    });
    g.finish();
}

criterion_group!(benches, bench_proving);
criterion_main!(benches);
