//! Performance benchmarks for ZK proof operations.
//!
//! Measures both wall-clock time and heap memory for each operation:
//! field byte conversions, ownership generation, witness generation,
//! and proof prove+verify round-trips.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "criterion benchmark harness reports memory/timing rows to stdout"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::rngs::OsRng;

use outbe_crypto_common::merkle::{MerklePathElement, MerklePathElementIndex};
use outbe_crypto_common::witness::{HashableNFT, OwnableNFT};
use outbe_zk_circuit_noir::{
    circuit_loader, testing, NoirCircuitConfig, NoirFullProofCircuit, NoirOwnershipCircuit,
    NoirProof, ZKCircuit, ZKMode,
};

// -- Tracking allocator --

struct TrackingAllocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let current = ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            // Update peak
            let mut peak = PEAK.load(Ordering::Relaxed);
            while current > peak {
                match PEAK.compare_exchange_weak(
                    peak,
                    current,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(p) => peak = p,
                }
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        ALLOCATED.fetch_sub(layout.size(), Ordering::Relaxed);
        DEALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

#[allow(dead_code)]
struct MemSnapshot {
    allocated: usize,
    peak: usize,
    alloc_count: usize,
    dealloc_count: usize,
}

fn reset_mem_stats() {
    // Don't reset ALLOCATED (it tracks live bytes), only peak and counts
    PEAK.store(ALLOCATED.load(Ordering::Relaxed), Ordering::Relaxed);
    ALLOC_COUNT.store(0, Ordering::Relaxed);
    DEALLOC_COUNT.store(0, Ordering::Relaxed);
}

fn snapshot_mem() -> MemSnapshot {
    MemSnapshot {
        allocated: ALLOCATED.load(Ordering::Relaxed),
        peak: PEAK.load(Ordering::Relaxed),
        alloc_count: ALLOC_COUNT.load(Ordering::Relaxed),
        dealloc_count: DEALLOC_COUNT.load(Ordering::Relaxed),
    }
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

// -- Minimal test NFT --

struct BenchNFT {
    ownership: Fr,
    nft_hash: Fr,
}

impl OwnableNFT for BenchNFT {
    fn ownership(&self) -> Fr {
        self.ownership
    }
}

impl HashableNFT for BenchNFT {
    fn hash(&self) -> Result<Fr, outbe_crypto_common::OutbeCryptoError> {
        Ok(self.nft_hash)
    }
}

fn make_bench_nft() -> (BenchNFT, testing::GrumpkinKey, Fr, Vec<MerklePathElement>) {
    let key = testing::random_grumpkin_key().expect("random grumpkin key");
    let nonce = Fr::rand(&mut OsRng);
    let ownership = testing::ownership_from_grumpkin_key(&key, nonce).unwrap();
    let nft_hash = Fr::rand(&mut OsRng);

    let mut merkle_path = Vec::with_capacity(6);
    for _ in 0..6 {
        let hash = Fr::rand(&mut OsRng);
        merkle_path.push(MerklePathElement {
            node_hash: testing::fr_to_le32(&hash),
            index: if rand::random() {
                MerklePathElementIndex::Left
            } else {
                MerklePathElementIndex::Right
            },
        });
    }

    (
        BenchNFT {
            ownership,
            nft_hash,
        },
        key,
        nonce,
        merkle_path,
    )
}

fn clone_proof(p: &NoirProof) -> NoirProof {
    NoirProof {
        proof: p.proof.clone(),
        public_inputs: p.public_inputs.clone(),
    }
}

// -- Benchmark harness --

struct BenchResult {
    name: String,
    iterations: u32,
    total_time: std::time::Duration,
    peak_heap: usize,
    alloc_count: usize,
    heap_after: usize,
    heap_before: usize,
}

impl BenchResult {
    fn avg_time(&self) -> std::time::Duration {
        self.total_time / self.iterations
    }

    fn net_heap(&self) -> isize {
        self.heap_after as isize - self.heap_before as isize
    }
}

fn bench<F: FnMut()>(name: &str, iterations: u32, mut f: F) -> BenchResult {
    // Warmup
    for _ in 0..std::cmp::min(3, iterations) {
        f();
    }

    let heap_before = ALLOCATED.load(Ordering::Relaxed);
    reset_mem_stats();

    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let total_time = start.elapsed();
    let mem = snapshot_mem();

    BenchResult {
        name: name.to_string(),
        iterations,
        total_time,
        peak_heap: mem.peak,
        alloc_count: mem.alloc_count,
        heap_after: mem.allocated,
        heap_before,
    }
}

fn print_header() {
    println!(
        "\n{:<35} {:>12} {:>14} {:>12} {:>14}",
        "Operation", "Avg Time", "Peak Heap", "Allocs", "Net Heap"
    );
    println!("{}", "-".repeat(89));
}

fn print_result(r: &BenchResult) {
    let avg = r.avg_time();
    let avg_str = if avg.as_nanos() < 1000 {
        format!("{} ns", avg.as_nanos())
    } else if avg.as_micros() < 1000 {
        format!("{:.1} µs", avg.as_nanos() as f64 / 1000.0)
    } else if avg.as_millis() < 1000 {
        format!("{:.2} ms", avg.as_micros() as f64 / 1000.0)
    } else {
        format!("{:.2} s", avg.as_millis() as f64 / 1000.0)
    };

    let net = r.net_heap();
    let net_str = if net == 0 {
        "0 B".to_string()
    } else if net > 0 {
        format!("+{}", format_bytes(net as usize))
    } else {
        format!("-{}", format_bytes((-net) as usize))
    };

    println!(
        "{:<35} {:>12} {:>14} {:>12} {:>14}",
        r.name,
        avg_str,
        format_bytes(r.peak_heap),
        r.alloc_count / r.iterations as usize,
        net_str,
    );
}

fn main() {
    println!("=== Outbe ZK Proof Performance Benchmark ===");

    // -- Field operations --
    print_header();

    let fr = Fr::rand(&mut OsRng);
    let bytes: [u8; 32] = testing::fr_to_le32(&fr);

    let r = bench("Fr::to_bytes_le", 100_000, || {
        std::hint::black_box(testing::fr_to_le32(std::hint::black_box(&fr)));
    });
    print_result(&r);

    let r = bench("Fr::from_bytes_le_mod_order", 100_000, || {
        use ark_ff::PrimeField;
        std::hint::black_box(Fr::from_le_bytes_mod_order(std::hint::black_box(&bytes)));
    });
    print_result(&r);

    // -- Crypto operations --
    let key = testing::random_grumpkin_key().expect("random grumpkin key");
    let nonce = Fr::rand(&mut OsRng);

    let r = bench("compute_ownership (Poseidon3)", 1_000, || {
        std::hint::black_box(testing::ownership_from_grumpkin_key(&key, nonce).unwrap());
    });
    print_result(&r);

    // -- Witness generation --
    let (nft, key, nonce, merkle_path) = make_bench_nft();

    let r = bench("ownership witness generation", 1_000, || {
        std::hint::black_box(testing::build_ownership_witness(&nft, &key, nonce).unwrap());
    });
    print_result(&r);

    let r = bench("full proof witness generation", 1_000, || {
        std::hint::black_box(
            testing::build_full_proof_witness(&nft, &key, nonce, &merkle_path).unwrap(),
        );
    });
    print_result(&r);

    // -- Proof operations --
    let (nft, key, nonce, _) = make_bench_nft();

    let ownership_witness = testing::build_ownership_witness(&nft, &key, nonce).unwrap();

    let ownership_bytecode = circuit_loader::load_circuit("data/ownership_proof.json").unwrap();
    let ownership_circuit = NoirOwnershipCircuit::setup(NoirCircuitConfig {
        circuit: ownership_bytecode,
        version: "0.0.1",
        low_memory: false,
        scheme: ZKMode::UltraHonkKeccak,
    })
    .unwrap();

    let r = bench("ownership prove", 5, || {
        std::hint::black_box(ownership_circuit.prove(ownership_witness.clone()).unwrap());
    });
    print_result(&r);

    let ownership_proof = ownership_circuit.prove(ownership_witness).unwrap();
    let r = bench("ownership verify", 20, || {
        std::hint::black_box(
            ownership_circuit
                .verify(clone_proof(&ownership_proof))
                .unwrap(),
        );
    });
    print_result(&r);

    // Full proof circuit
    let (nft2, key2, nonce2, merkle_path2) = make_bench_nft();
    let full_witness =
        testing::build_full_proof_witness(&nft2, &key2, nonce2, &merkle_path2).unwrap();

    let full_bytecode = circuit_loader::load_circuit("data/full_proof.json").unwrap();
    let full_circuit = NoirFullProofCircuit::setup(NoirCircuitConfig {
        circuit: full_bytecode,
        version: "0.0.1",
        low_memory: false,
        scheme: ZKMode::UltraHonkKeccak,
    })
    .unwrap();

    let r = bench("full_proof prove", 5, || {
        std::hint::black_box(full_circuit.prove(full_witness.clone()).unwrap());
    });
    print_result(&r);

    let full_proof = full_circuit.prove(full_witness).unwrap();
    let r = bench("full_proof verify", 20, || {
        std::hint::black_box(full_circuit.verify(clone_proof(&full_proof)).unwrap());
    });
    print_result(&r);

    println!();
}
