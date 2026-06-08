//! One-off profiling helper: measure PK-build cost of a compiled Noir
//! circuit via the same noir_rs FFI path the prover uses.
//!
//! Usage:
//!   cargo run --release --example measure_pk -- <path/to/circuit.json>

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI profiling example that reports timing to stdout"
)]
//!
//! Loads the bytecode and invokes `derive_canonical_keccak_vk`. noir_rs
//! prints its own `CircuitProve: Proving key computed in X ms (mem: Y MiB)`
//! line during the FFI call; we wrap that with wall-clock + macOS peak RSS.
//!
//! Intended for ad-hoc circuit cost comparisons (e.g. when evaluating
//! changes to `outbe-circuit-core::recursion` that affect the in-circuit
//! verifier cost of `verify_honk_proof_non_zk`).

use std::time::Instant;

fn read_bytecode_b64(path: &str) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&raw)?;
    let bc = json
        .get("bytecode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing 'bytecode' field"))?
        .trim()
        .to_string();
    Ok(bc)
}

fn peak_rss_mib() -> Option<f64> {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    if rc != 0 {
        return None;
    }
    let max_rss = ru.ru_maxrss as f64;
    #[cfg(target_os = "macos")]
    let mib = max_rss / (1024.0 * 1024.0);
    #[cfg(not(target_os = "macos"))]
    let mib = max_rss / 1024.0;
    Some(mib)
}

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: measure_pk <circuit.json>"))?;

    let bc_b64 = read_bytecode_b64(&path)?;
    println!("circuit: {path}");
    println!("bytecode (b64): {} bytes", bc_b64.len());

    let t0 = Instant::now();
    let vk = outbe_zk_circuit_noir::derive_canonical_keccak_vk(&bc_b64)?;
    let elapsed = t0.elapsed();
    let rss = peak_rss_mib().unwrap_or(-1.0);

    println!(
        "derive_canonical_keccak_vk: {:.2}s  vk={} bytes  peak_rss={:.2} MiB",
        elapsed.as_secs_f64(),
        vk.len(),
        rss
    );

    Ok(())
}
