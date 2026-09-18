#![allow(clippy::print_stdout)] // diagnostic #[ignore]d tests that print pin/complexity tables
//! Regenerate the `PINNED_G1_SHA256` table in `barretenberg/srs.rs`.
//!
//! For every circuit this repository proves — the two L1 circuits and the L2
//! demo tribute root — it computes the SRS point count bb actually needs
//! (`circuit_stats` → dyadic domain `+ 1`; no proving, so it's fast) and the
//! SHA-256 of that G1 prefix from the local Aztec CRS, then does the same for
//! the two sizes nothing derives from a circuit: the demo bench's one tier of
//! headroom over the largest circuit, and `CANONICAL_SRS_POINTS`, the size
//! `init_crs` fixes. Those five printed rows are where the pin table comes from
//! and the table holds no size they do not cover — but emit mint and paynote
//! share the 2^14 domain, so they print the same row twice; drop the duplicate
//! when pasting. Ignored by default (needs the local CRS +
//! libbb); run:
//!   cargo test -p outbe-zk-backend --test srs_pins -- --ignored --nocapture
//! then paste the printed `(points, [..])` rows into `PINNED_G1_SHA256`.

use std::io::Read;

use barretenberg_rs::api::BarretenbergApi;
use barretenberg_rs::backends::FfiBackend;
use barretenberg_rs::generated_types::{CircuitInput, ProofSystemSettings};
use base64::Engine;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};

use outbe_zk_backend::barretenberg::CANONICAL_SRS_POINTS;
use outbe_zk_canonical::noir::emit_mint::EmitMint;
use outbe_zk_canonical::noir::paynote::Paynote;
use outbe_zk_canonical::CircuitId;

const G1_POINT_SIZE: usize = 64;

/// The L2 demo tribute root's ACIR — the largest circuit in the repo, and the
/// only one outside `outbe-zk-canonical`. The file belongs to `outbe-l2-demo`,
/// not to `outbe-l2-zk-canonical`, and `outbe-l2-demo` already depends on this
/// crate — so depending on it back would close a dependency cycle. Reading the
/// committed file by path adds no package edge. `outbe-l2-demo`'s `build.rs`
/// checks these bytes against the root's `circuit.hash`.
const TRIBUTE_BYTECODE_B64: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/outbe-l2-demo/resources/bytecode.b64"
));

/// Every circuit this repo proves, largest last. The SRS point count is derived
/// from the bytecode, so this list IS the answer to "which sizes need a pin".
fn circuits() -> Vec<(&'static str, &'static str)> {
    vec![
        ("emit mint", EmitMint::BYTECODE_B64),
        ("paynote", Paynote::BYTECODE_B64),
        ("L2 demo tribute root", TRIBUTE_BYTECODE_B64),
    ]
}

/// UltraHonk + keccak, ZK on — matches `Barretenberg::default()` / the prover,
/// so the gate count (and thus point count) matches what proving actually sizes.
fn keccak_settings() -> ProofSystemSettings {
    ProofSystemSettings {
        ipa_accumulation: false,
        oracle_hash_type: "keccak".to_string(),
        disable_zk: false,
        optimized_solidity_verifier: false,
    }
}

fn acir(b64: &str) -> Vec<u8> {
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .unwrap();
    let mut raw = Vec::new();
    GzDecoder::new(compressed.as_slice())
        .read_to_end(&mut raw)
        .unwrap();
    raw
}

fn cache_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("BB_CRS_PATH") {
        return p.into();
    }
    std::path::Path::new(&std::env::var("HOME").unwrap_or_default()).join(".bb-crs/bn254_g1.dat")
}

fn num_points(api: &mut BarretenbergApi<FfiBackend>, acir: &[u8]) -> u32 {
    let circuit = CircuitInput {
        name: String::new(),
        bytecode: acir.to_vec(),
        verification_key: Vec::new(),
    };
    let info = api
        .circuit_stats(circuit, false, keccak_settings())
        .unwrap();
    info.num_gates_dyadic
        .max(info.num_gates.next_power_of_two())
        + 1
}

fn pin_row(label: &str, n: u32) -> String {
    let bytes = std::fs::read(cache_path()).unwrap();
    let need = n as usize * G1_POINT_SIZE;
    assert!(
        bytes.len() >= need,
        "local CRS too small for {label} ({need} bytes)"
    );
    let digest = Sha256::digest(&bytes[..need]);
    let body: Vec<String> = digest.iter().map(|b| format!("0x{b:02x}")).collect();
    format!("    // {label}\n    ({n}, [{}]),", body.join(", "))
}

#[test]
#[ignore = "regen helper: needs local CRS + libbb; run with --ignored --nocapture"]
fn print_srs_pins() {
    let backend = FfiBackend::new().unwrap();
    let mut api = BarretenbergApi::new(backend);
    println!("\n--- paste into PINNED_G1_SHA256 ---");
    let mut largest = 0;
    for (label, b64) in circuits() {
        let n = num_points(&mut api, &acir(b64));
        largest = largest.max(n);
        println!("{}", pin_row(label, n));
    }
    // Not a circuit's own size: `examples/outbe-l2-demo/benches/proving.rs`
    // hands `preinit_srs` the literal `(1 << 17) + 1`, one dyadic tier above the
    // largest circuit (the tribute root's 2^16), so that is a size a prover
    // really hands to `srs_init_srs`. This recomputes the tier from the same
    // bytecode instead of reading the bench: if the printed row ever stops
    // matching the bench's literal, one of the two is stale.
    println!(
        "{}",
        pin_row(
            "l2 demo bench preinit (one tier over the largest circuit)",
            (largest - 1) * 2 + 1
        )
    );
    // Likewise not a circuit's size: the one `init_crs` initializes to. No
    // prover here asks for it — each sizes the CRS from its own circuit — but
    // `init_crs` is the startup call an embedding application makes, and
    // `tests/crs_init.rs` runs it, so those bytes do reach `srs_init_srs`.
    println!(
        "{}",
        pin_row("init_crs / CANONICAL_SRS_POINTS", CANONICAL_SRS_POINTS)
    );
    println!("--- end ---\n");
}

fn gate_counts(api: &mut BarretenbergApi<FfiBackend>, acir: &[u8]) -> (u32, u32) {
    let circuit = CircuitInput {
        name: String::new(),
        bytecode: acir.to_vec(),
        verification_key: Vec::new(),
    };
    let info = api
        .circuit_stats(circuit, false, keccak_settings())
        .unwrap();
    (info.num_gates, info.num_gates_dyadic)
}

/// Print a markdown table of each circuit's gate count (UltraHonkKeccak, ZK on).
/// Capture before/after a hash swap to measure the complexity delta:
///   cargo test -p outbe-zk-backend --test srs_pins print_circuit_complexity -- --ignored --nocapture
#[test]
#[ignore = "complexity capture: needs libbb; run with --ignored --nocapture"]
fn print_circuit_complexity() {
    let backend = FfiBackend::new().unwrap();
    let mut api = BarretenbergApi::new(backend);
    println!("\n--- circuit complexity ---");
    println!("| circuit | num_gates | dyadic (2^k) |");
    println!("|---|---|---|");
    for (label, b64) in circuits() {
        let (g, d) = gate_counts(&mut api, &acir(b64));
        println!("| {label} | {g} | {d} |");
    }
    println!("--- end ---\n");
}
