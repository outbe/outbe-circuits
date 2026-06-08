//! Prove-time cost matrix for the per-SU ownership circuit.
//!
//! The PK-build matrix (`cost_matrix`) doesn't show `low_memory` effects
//! because `circuit_compute_vk` doesn't allocate the polynomial
//! workspaces that low_memory mode targets. The actual cost on a mobile

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI example binary that streams JSON cost rows to stdout"
)]
//! prover is the full `prove_ultra_honk_keccak` path, which IS affected
//! by low_memory.
//!
//! This binary runs ONE cell — a single end-to-end prove of the
//! ownership circuit — and reports wall-clock + peak RSS. Driven cell-
//! by-cell by `scripts/run_cost_matrix.sh`.
//!
//! Usage:
//!   ownership_prove_matrix --oracle <keccak|poseidon2> --zk <on|off> --low-mem <on|off> --label <name>

use std::time::Instant;

use outbe_zk_circuit_noir::{
    circuit_loader, testing, NoirCircuitConfig, NoirOwnershipCircuit, ZKCircuit, ZKMode,
};

use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::rngs::OsRng;

use outbe_crypto_common::witness::{HashableNFT, OwnableNFT};

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

fn arg(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

fn peak_rss_mib() -> f64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
        return -1.0;
    }
    let max_rss = ru.ru_maxrss as f64;
    #[cfg(target_os = "macos")]
    let mib = max_rss / (1024.0 * 1024.0);
    #[cfg(not(target_os = "macos"))]
    let mib = max_rss / 1024.0;
    mib
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let oracle = arg(&args, "--oracle").unwrap_or_else(|| "keccak".to_string());
    let zk_on = arg(&args, "--zk").unwrap_or_else(|| "off".to_string()) == "on";
    let low_mem = arg(&args, "--low-mem").unwrap_or_else(|| "off".to_string()) == "on";
    let label = arg(&args, "--label").unwrap_or_default();

    // configure_memory writes both env vars and the C++ globals so
    // low_memory actually takes effect inside the prove path.
    outbe_zk_circuit_noir::barretenberg::api::configure_memory(low_mem, None);

    // Build a real witness for the ownership circuit.
    let key = testing::random_grumpkin_key().expect("random grumpkin key");
    let nonce = Fr::rand(&mut OsRng);
    let ownership = testing::ownership_from_grumpkin_key(&key, nonce).unwrap();
    let nft_hash = Fr::rand(&mut OsRng);
    let nft = BenchNFT {
        ownership,
        nft_hash,
    };
    let witness = match testing::build_ownership_witness(&nft, &key, nonce) {
        Ok(w) => w,
        Err(e) => {
            println!(
                r#"{{"label":"{}","ok":false,"error":"witness: {}"}}"#,
                label,
                e.to_string().replace('"', "'")
            );
            return;
        }
    };

    // Resolve relative to the crate dir so we can be invoked from any cwd.
    let circuit_path = std::env::var("OUTBE_OWNERSHIP_JSON")
        .unwrap_or_else(|_| format!("{}/data/ownership_proof.json", env!("CARGO_MANIFEST_DIR")));
    let bytecode = match circuit_loader::load_circuit(&circuit_path) {
        Ok(b) => b,
        Err(e) => {
            println!(
                r#"{{"label":"{}","ok":false,"error":"load_circuit: {}"}}"#,
                label,
                e.to_string().replace('"', "'")
            );
            return;
        }
    };

    let scheme = match oracle.as_str() {
        "keccak" => ZKMode::UltraHonkKeccak,
        "poseidon2" => ZKMode::UltraHonk,
        other => {
            println!(
                r#"{{"label":"{}","ok":false,"error":"unknown oracle '{}'"}}"#,
                label, other
            );
            return;
        }
    };

    // zk_on parameter: the prover variants we have only differ at the
    // scheme level; UltraHonk vs UltraHonkKeccak both have ZK by
    // default. The non-zk variants aren't currently in NoirCircuitConfig,
    // so we report zk_on as informational.
    let config = NoirCircuitConfig {
        circuit: bytecode,
        version: "0.0.1",
        low_memory: low_mem,
        scheme,
    };

    let circuit = match NoirOwnershipCircuit::setup(config) {
        Ok(c) => c,
        Err(e) => {
            println!(
                r#"{{"label":"{}","ok":false,"error":"setup: {}"}}"#,
                label,
                e.to_string().replace('"', "'")
            );
            return;
        }
    };

    let t0 = Instant::now();
    let proof = match circuit.prove(witness) {
        Ok(p) => p,
        Err(e) => {
            println!(
                r#"{{"label":"{}","ok":false,"error":"prove: {}"}}"#,
                label,
                e.to_string().replace('"', "'")
            );
            return;
        }
    };
    let elapsed = t0.elapsed();
    let rss = peak_rss_mib();

    println!(
        r#"{{"label":"{}","oracle":"{}","zk":{},"low_mem":{},"proof_bytes":{},"public_inputs":{},"prove_ms":{},"peak_rss_mib":{:.2},"ok":true}}"#,
        label,
        oracle,
        zk_on,
        low_mem,
        proof.proof.len(),
        proof.public_inputs.len(),
        elapsed.as_millis(),
        rss
    );
}
