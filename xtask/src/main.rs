//! Build orchestration for the Outbe ZK proof workspace.
//!
//! Usage:
//!   cargo xtask compile-circuits         # Compile Noir circuits and copy bytecodes
//!   cargo xtask regenerate-canonical     # Regenerate VKs + circuit hashes in outbe-zk-canonical

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "xtask is a developer CLI tool that prints progress / status to stdout"
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

// -- CLI --

#[derive(Parser)]
#[command(name = "xtask", about = "Outbe ZK proof workspace tasks")]
struct Cli {
    #[command(subcommand)]
    command: Tasks,
}

#[derive(Subcommand)]
enum Tasks {
    /// Compile Noir circuits and copy bytecodes to data/.
    CompileCircuits,

    /// Regenerate the `outbe-zk-canonical` crate from currently-compiled
    /// circuits: derive UltraHonkKeccak VKs, compute circuit_hash +
    /// vk_hash, write VK byte files, and emit the const declarations
    /// in `crates/outbe-zk-canonical/src/lib.rs`.
    ///
    /// Prerequisites (install via the official toolchain installers,
    /// no need to build C++ from source):
    ///
    ///   curl -L noirup.dev | bash        # then: `noirup`
    ///   curl -L bbup.dev   | bash        # then: `bbup`
    ///
    /// The xtask shells out to `nargo` (already used by compile-circuits)
    /// and `bb` (Barretenberg CLI) — no FFI link required.
    ///
    /// See outbe-chain/docs/issues/zk-circuit-table-and-rollout.md for
    /// the consumer-side spec.
    RegenerateCanonical {
        /// If set, regenerate to a tempfile and compare against the
        /// committed state instead of writing in place. Fails on any
        /// diff. For CI gating.
        #[arg(long)]
        check: bool,
    },
}

// -- Toolchain version pin --

/// Required nargo CLI version. Must match the `v1.0.0-beta.XX` git
/// tag pinned for the `acvm` / `acvm_blackbox_solver` /
/// `bn254_blackbox_solver` / `nargo` deps in the workspace Cargo.toml.
/// Bump both together when chasing a noir release — otherwise the
/// installed CLI binary silently drifts from the FFI proving stack,
/// embedding a mismatched version in compiled artifacts.
const EXPECTED_NARGO_VERSION: &str = "1.0.0-beta.20";

// -- Circuit definitions --

struct CircuitDef {
    /// Human-readable name for logging.
    name: &'static str,
    /// Directory containing Nargo.toml (relative to circuit_base).
    dir: &'static str,
    /// Output filename produced by nargo compile (matches package name in Nargo.toml).
    output_file: &'static str,
}

const CIRCUITS: &[CircuitDef] = &[
    CircuitDef {
        name: "full proof",
        dir: "outbe-full-circuit",
        output_file: "full_proof.json",
    },
    CircuitDef {
        name: "ownership proof",
        dir: "outbe-ownership-circuit",
        output_file: "ownership_proof.json",
    },
];

/// If `dir` matches the flat-aggregation tier pattern, return the
/// tier `N`. Used by `circuit_short_name` / `circuit_const_ident` /
/// `circuit_label` so we don't repeat the 7 mappings three times.
fn aggregation_tier_n(dir: &str) -> Option<u32> {
    dir.strip_prefix("outbe-flat-aggregation-circuit-n")
        .and_then(|s| s.parse::<u32>().ok())
}

// -- Paths --

fn project_root() -> Result<PathBuf> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .context("CARGO_MANIFEST_DIR not set — run via `cargo xtask`")?;
    let root = Path::new(&manifest_dir)
        .parent()
        .context("xtask must be at <root>/xtask")?
        .to_path_buf();
    Ok(root)
}

fn circuit_base(root: &Path) -> PathBuf {
    root.join("crates/outbe-zk-circuit-noir")
}

fn data_dir(root: &Path) -> PathBuf {
    circuit_base(root).join("data")
}

// -- Commands --

fn compile_circuits() -> Result<()> {
    let root = project_root()?;
    let base = circuit_base(&root);
    let data = data_dir(&root);

    // Ensure data directory exists.
    fs::create_dir_all(&data).with_context(|| format!("failed to create {}", data.display()))?;

    // Verify nargo is available.
    let nargo = find_nargo()?;
    println!("Using nargo: {}", nargo.display());

    for circuit in CIRCUITS {
        let circuit_dir = base.join(circuit.dir);
        println!("\n--- Compiling {} ---", circuit.name);

        let status = Command::new(&nargo)
            .arg("compile")
            .current_dir(&circuit_dir)
            .status()
            .with_context(|| format!("failed to run nargo compile in {}", circuit_dir.display()))?;

        if !status.success() {
            bail!(
                "nargo compile failed for {} (exit code: {:?})",
                circuit.name,
                status.code()
            );
        }

        // Copy compiled output to data/.
        let src = circuit_dir.join("target").join(circuit.output_file);
        let dst = data.join(circuit.output_file);

        if !src.exists() {
            bail!(
                "expected compiled output at {} but file does not exist",
                src.display()
            );
        }

        fs::copy(&src, &dst)
            .with_context(|| format!("failed to copy {} → {}", src.display(), dst.display()))?;

        let size = fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);
        println!(
            "  Copied {} → {} ({} KB)",
            src.display(),
            dst.display(),
            size / 1024
        );
    }

    println!("\nAll circuits compiled successfully.");
    Ok(())
}

// -- Helpers --

fn find_nargo() -> Result<PathBuf> {
    // Check common locations.
    let home = env::var("HOME").unwrap_or_default();
    let nargo_home = Path::new(&home).join(".nargo/bin/nargo");

    let path = if nargo_home.exists() {
        nargo_home
    } else {
        which_in_path("nargo")?
    };

    check_nargo_version(&path)?;
    Ok(path)
}

fn check_nargo_version(nargo: &Path) -> Result<()> {
    let out = Command::new(nargo)
        .arg("--version")
        .output()
        .with_context(|| format!("failed to run {} --version", nargo.display()))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !stdout.contains(EXPECTED_NARGO_VERSION) && !stderr.contains(EXPECTED_NARGO_VERSION) {
        bail!(
            "nargo {EXPECTED_NARGO_VERSION} required, found:\n{stdout}{stderr}\n\
             Install the matching version: noirup -v {EXPECTED_NARGO_VERSION}"
        );
    }
    Ok(())
}

fn which_in_path(binary: &str) -> Result<PathBuf> {
    let output = Command::new("which")
        .arg(binary)
        .output()
        .with_context(|| format!("failed to locate {binary}"))?;

    if !output.status.success() {
        bail!(
            "{binary} not found. Install it from https://noir-lang.org/docs/getting_started/installation"
        );
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(path))
}

// -- Entry point --

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Tasks::CompileCircuits => compile_circuits(),
        Tasks::RegenerateCanonical { check } => regenerate_canonical(check),
    }
}

// -- outbe-zk-canonical regeneration --
//
// Two phases:
// 1. `nargo compile` — pure subprocess against the installed nargo
//    binary; produces ACIR JSON per circuit.
// 2. VK derivation — via `outbe_zk_circuit_noir::derive_canonical_keccak_vk`,
//    which goes through the noir_rs FFI (and thus pulls the
//    barretenberg static library at xtask build time). This is the
//    same FFI the prover uses, guaranteeing the VK we ship as canonical
//    accepts proofs that wallets produce in the field.
//
// Build-time cost: first compile of xtask drags in the barretenberg
// C++ static lib (~minutes). Subsequent compiles are incremental.

fn regenerate_canonical(check: bool) -> Result<()> {
    use base64::Engine;

    println!("=== regenerate-canonical (check={check}) ===\n");

    // Phase 0: compile every circuit (no-op if up-to-date).
    compile_circuits()?;

    let root = project_root()?;
    let data = data_dir(&root);
    let canonical_dir = root.join("crates/outbe-zk-canonical");
    let vks_dir = canonical_dir.join("res/vks");
    fs::create_dir_all(&vks_dir)
        .with_context(|| format!("failed to create {}", vks_dir.display()))?;

    let mut descriptors: Vec<GeneratedDescriptor> = Vec::new();

    for circuit in CIRCUITS {
        let json_path = data.join(circuit.output_file);
        println!("\n--- {} ({}) ---", circuit.name, json_path.display());

        // Extract base64 ACIR bytecode from the compiled JSON.
        let raw = fs::read_to_string(&json_path)
            .with_context(|| format!("read {}", json_path.display()))?;
        let json: serde_json::Value = serde_json::from_str(&raw)
            .with_context(|| format!("parse JSON: {}", json_path.display()))?;
        let bytecode_b64 = json
            .get("bytecode")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'bytecode' in {}", json_path.display()))?
            .trim()
            .to_string();

        // circuit_hash = keccak256(base64_decode(bytecode)).
        // Content-addressed identifier — different source → different hash.
        let acir_bytes = base64::engine::general_purpose::STANDARD
            .decode(&bytecode_b64)
            .with_context(|| format!("base64 decode bytecode for {}", circuit.name))?;
        let circuit_hash = keccak256(&acir_bytes);

        // Derive VK via the noir_rs FFI through outbe-zk-circuit-noir.
        // This must be the same path the prover uses (verifier side
        // calls `verify_ultra_honk_keccak` and provers call
        // `prove_ultra_honk_keccak`, both via the same FFI). The
        // previous bb-CLI path produced bytes that didn't verify
        // against real proofs — see `docs/issues/zk-circuit-table-and-rollout.md`.
        let short_name = circuit_short_name(circuit);
        let vk_bytes = outbe_zk_circuit_noir::derive_canonical_keccak_vk(&bytecode_b64)
            .with_context(|| format!("derive VK for {}", circuit.name))?;
        let vk_hash = keccak256(&vk_bytes);
        let vk_path = vks_dir.join(format!("{short_name}.vk"));

        if check {
            check_bytes_match(&vk_path, &vk_bytes)
                .with_context(|| format!("VK drift for {}", circuit.name))?;
        } else {
            fs::write(&vk_path, &vk_bytes)
                .with_context(|| format!("write {}", vk_path.display()))?;
        }

        println!(
            "  acir={} B  circuit_hash={}  vk={} B  vk_hash={}",
            acir_bytes.len(),
            hex32(&circuit_hash),
            vk_bytes.len(),
            hex32(&vk_hash),
        );

        descriptors.push(GeneratedDescriptor {
            const_ident: circuit_const_ident(circuit),
            label: circuit_label(circuit),
            version: "1.0.0", // TODO: source from per-circuit manifest
            short_name: short_name.clone(),
            circuit_hash,
            vk_hash,
        });
    }

    // Phase 2: regenerate lib.rs (between BEGIN/END GENERATED markers).
    let lib_path = canonical_dir.join("src/lib.rs");
    let existing =
        fs::read_to_string(&lib_path).with_context(|| format!("read {}", lib_path.display()))?;
    let regenerated = splice_generated_block(&existing, &descriptors)?;

    if check {
        if existing != regenerated {
            bail!(
                "outbe-zk-canonical/src/lib.rs is stale.\n\
                 Run `cargo run -p xtask -- regenerate-canonical` (no --check) to \
                 update, then commit the result."
            );
        }
    } else {
        fs::write(&lib_path, &regenerated)
            .with_context(|| format!("write {}", lib_path.display()))?;
    }

    println!("\n{} circuit(s) processed.", descriptors.len());
    if check {
        println!("--check passed: committed state matches regeneration.");
    } else {
        println!(
            "Wrote {} VK file(s) + regenerated lib.rs.",
            descriptors.len()
        );
    }
    Ok(())
}

struct GeneratedDescriptor {
    /// Rust identifier for the const, e.g. "OWNERSHIP" or "FULL_PROOF".
    const_ident: String,
    /// Human-readable label, e.g. "outbe.ownership" or "outbe.full_proof".
    label: String,
    /// Semver-style version string. Constant for now; later sourced from
    /// a per-circuit manifest.
    version: &'static str,
    /// Filename stem under res/vks/.
    short_name: String,
    circuit_hash: [u8; 32],
    vk_hash: [u8; 32],
}

fn circuit_short_name(c: &CircuitDef) -> String {
    // Map CIRCUITS entries to filesystem-safe short names. Explicit so
    // the mapping is auditable.
    match c.dir {
        "outbe-ownership-circuit" => "ownership".to_string(),
        "outbe-full-circuit" => "full_proof".to_string(),
        other => {
            if let Some(n) = aggregation_tier_n(other) {
                format!("flat_aggregation_n{n}")
            } else {
                panic!("unmapped circuit dir: {other}")
            }
        }
    }
}

fn circuit_const_ident(c: &CircuitDef) -> String {
    match c.dir {
        "outbe-ownership-circuit" => "OWNERSHIP".to_string(),
        "outbe-full-circuit" => "FULL_PROOF".to_string(),
        other => {
            if let Some(n) = aggregation_tier_n(other) {
                format!("FLAT_AGGREGATION_N{n}")
            } else {
                panic!("unmapped circuit dir: {other}")
            }
        }
    }
}

fn circuit_label(c: &CircuitDef) -> String {
    match c.dir {
        "outbe-ownership-circuit" => "outbe.ownership".to_string(),
        "outbe-full-circuit" => "outbe.full_proof".to_string(),
        other => {
            if let Some(n) = aggregation_tier_n(other) {
                format!("outbe.flat_aggregation.n{n}")
            } else {
                panic!("unmapped circuit dir: {other}")
            }
        }
    }
}

fn keccak256(input: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(2 + 64);
    s.push_str("0x");
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn hex64(b: &[u8; 32]) -> String {
    // 64 hex chars, no 0x prefix (matches what hex_literal::hex! expects).
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn check_bytes_match(path: &Path, expected: &[u8]) -> Result<()> {
    if !path.exists() {
        bail!("{} missing — run without --check first", path.display());
    }
    let on_disk = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if on_disk != expected {
        bail!(
            "{} differs from regeneration ({} vs {} bytes). Run \
             regenerate-canonical without --check and commit.",
            path.display(),
            on_disk.len(),
            expected.len(),
        );
    }
    Ok(())
}

const GEN_BEGIN: &str =
    "// === BEGIN GENERATED — do not edit (run `cargo xtask regenerate-canonical`) ===";
const GEN_END: &str = "// === END GENERATED ===";

fn splice_generated_block(existing: &str, descs: &[GeneratedDescriptor]) -> Result<String> {
    let begin_idx = existing
        .find(GEN_BEGIN)
        .context("BEGIN GENERATED marker missing from src/lib.rs")?;
    let end_idx = existing
        .find(GEN_END)
        .context("END GENERATED marker missing from src/lib.rs")?;
    if end_idx <= begin_idx {
        bail!("END GENERATED appears before BEGIN GENERATED in src/lib.rs");
    }

    let mut out = String::with_capacity(existing.len() + 1024);
    out.push_str(&existing[..begin_idx]);
    out.push_str(GEN_BEGIN);
    out.push('\n');

    // Per-circuit const declarations.
    for d in descs {
        out.push_str(&format!(
            "\npub const {ident}: CircuitDescriptor = CircuitDescriptor {{\n    \
                circuit_hash: hex_literal::hex!(\"{ch}\"),\n    \
                label:        \"{label}\",\n    \
                version:      \"{version}\",\n    \
                vk_bytes:     include_bytes!(\"../res/vks/{short}.vk\"),\n    \
                vk_hash:      hex_literal::hex!(\"{vh}\"),\n}};\n",
            ident = d.const_ident,
            ch = hex64(&d.circuit_hash),
            label = d.label,
            version = d.version,
            short = d.short_name,
            vh = hex64(&d.vk_hash),
        ));
    }

    // ALL_CIRCUITS table.
    out.push_str("\npub const ALL_CIRCUITS: &[&CircuitDescriptor] = &[\n");
    for d in descs {
        out.push_str(&format!("    &{},\n", d.const_ident));
    }
    out.push_str("];\n");

    out.push_str(GEN_END);
    out.push_str(&existing[end_idx + GEN_END.len()..]);

    Ok(out)
}
