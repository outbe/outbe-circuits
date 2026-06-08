//! Build orchestration for the Outbe ZK proof workspace.
//!
//! Usage:
//!   cargo xtask compile-circuits         # Compile Noir circuits and copy bytecodes
//!   cargo xtask build-mobile <target>    # Compile circuits + build mobile crate

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "xtask is a developer CLI tool that prints progress / status to stdout"
)]
//!   cargo xtask build-kotlin [--targets] # Build Kotlin JAR with native libs + UniFFI bindings

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

    /// Compile circuits, then build the mobile crate for a target.
    BuildMobile {
        /// Rust target triple (e.g., aarch64-apple-ios).
        target: String,

        /// Enable dev-tools feature.
        #[arg(long)]
        dev_tools: bool,
    },

    /// Build Kotlin JAR with native libraries and UniFFI bindings.
    ///
    /// Produces a JAR containing compiled Kotlin bindings, a NativeLoader,
    /// and native libraries for each specified target platform.
    BuildKotlin {
        /// Rust target triples to build (can be specified multiple times).
        /// Defaults to the current host target.
        #[arg(long, short)]
        targets: Vec<String>,
    },

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
    // Flat aggregation tiers. Each verifies N copies of
    // `outbe_circuit_core::ownership::verify_ownership_per_su` inline
    // (no recursive proof verification). Same source body, different
    // compile-time `N`. Used by the on-chain TributeDraft submission
    // gate (sec. 5.2 of the privacy-preserving L2 architecture).
    CircuitDef {
        name: "flat aggregation N=1",
        dir: "outbe-flat-aggregation-circuit-n1",
        output_file: "flat_aggregation_n1.json",
    },
    CircuitDef {
        name: "flat aggregation N=2",
        dir: "outbe-flat-aggregation-circuit-n2",
        output_file: "flat_aggregation_n2.json",
    },
    CircuitDef {
        name: "flat aggregation N=4",
        dir: "outbe-flat-aggregation-circuit-n4",
        output_file: "flat_aggregation_n4.json",
    },
    CircuitDef {
        name: "flat aggregation N=8",
        dir: "outbe-flat-aggregation-circuit-n8",
        output_file: "flat_aggregation_n8.json",
    },
    CircuitDef {
        name: "flat aggregation N=16",
        dir: "outbe-flat-aggregation-circuit-n16",
        output_file: "flat_aggregation_n16.json",
    },
    CircuitDef {
        name: "flat aggregation N=32",
        dir: "outbe-flat-aggregation-circuit-n32",
        output_file: "flat_aggregation_n32.json",
    },
    CircuitDef {
        name: "flat aggregation N=64",
        dir: "outbe-flat-aggregation-circuit-n64",
        output_file: "flat_aggregation_n64.json",
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

fn build_mobile(target: &str, dev_tools: bool) -> Result<()> {
    // Step 1: Compile circuits.
    compile_circuits()?;

    // Step 2: Build the mobile crate.
    let root = project_root()?;
    println!("\n--- Building outbe-mobile-integration for {} ---", target);

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--release")
        .arg("--target")
        .arg(target)
        .arg("-p")
        .arg("outbe-mobile-integration")
        .current_dir(&root);

    if dev_tools {
        cmd.arg("--features").arg("dev-tools");
    }

    let status = cmd
        .status()
        .context("failed to run cargo build for outbe-mobile-integration")?;

    if !status.success() {
        bail!("cargo build failed (exit code: {:?})", status.code());
    }

    println!("\nMobile build complete.");
    Ok(())
}

fn build_kotlin(targets: &[String]) -> Result<()> {
    let root = project_root()?;
    let og_dir = root.join("integrations/outbe-sra-integration");
    let kotlin_dir = og_dir.join("kotlin");

    // Determine targets — default to host platform.
    // Use -t to specify targets explicitly, e.g. for CI cross-compilation.
    let targets = if targets.is_empty() {
        vec![host_target()?]
    } else {
        targets.to_vec()
    };

    // Step 1: Build native library for each target.
    // Use `cargo zigbuild` for cross-compilation, `cargo build` for native.
    let host = host_target()?;
    for target in &targets {
        let is_cross = target != &host;
        let cargo_cmd = if is_cross { "zigbuild" } else { "build" };
        println!(
            "\n--- Building native library for {} ({}) ---",
            target,
            if is_cross { "cross via zig" } else { "native" }
        );

        if is_cross {
            // Verify cargo-zigbuild is available.
            which_in_path("cargo-zigbuild").context(
                "cargo-zigbuild not found. Install it: cargo install cargo-zigbuild\n\
                 Also requires zig: brew install zig",
            )?;
        }

        run_cmd(
            Command::new("cargo")
                .args([
                    cargo_cmd,
                    "-p",
                    "outbe-sra-integration",
                    "--release",
                    "--target",
                    target,
                ])
                .current_dir(&root),
            &format!("cargo {cargo_cmd} for {target}"),
        )?;
    }

    // Step 2: Build uniffi-bindgen binary (for host).
    println!("\n--- Building uniffi-bindgen ---");
    run_cmd(
        Command::new("cargo")
            .args([
                "build",
                "-p",
                "outbe-sra-integration",
                "--bin",
                "uniffi-bindgen-sra",
            ])
            .current_dir(&root),
        "cargo build uniffi-bindgen-sra",
    )?;

    // Step 3: Generate Kotlin bindings.
    // Use the host-built library for metadata extraction.
    let host_lib = root
        .join("target")
        .join(&host)
        .join("release")
        .join(native_lib_filename(&host));

    // Build for host if not already in the target list.
    if !host_lib.exists() {
        println!("\n--- Building host library for binding generation ---");
        run_cmd(
            Command::new("cargo")
                .args([
                    "build",
                    "-p",
                    "outbe-sra-integration",
                    "--release",
                    "--target",
                    &host,
                ])
                .current_dir(&root),
            "cargo build (host)",
        )?;
    }

    let gen_dir = kotlin_dir.join("src/main/kotlin");
    fs::create_dir_all(&gen_dir)?;

    println!("\n--- Generating Kotlin bindings ---");
    let uniffi_bindgen = root.join("target/debug/uniffi-bindgen-sra");
    let uniffi_config = kotlin_dir.join("uniffi.toml");
    run_cmd(
        Command::new(&uniffi_bindgen)
            .args([
                "generate",
                "--library",
                &host_lib.to_string_lossy(),
                "--language",
                "kotlin",
                "--out-dir",
                &gen_dir.to_string_lossy(),
                "--config",
                &uniffi_config.to_string_lossy(),
            ])
            .current_dir(&root),
        "uniffi-bindgen generate",
    )?;

    // Step 4: Copy native libraries into Gradle resources.
    // JNA-compatible paths: {os}-{arch}/ at the resource root.
    for target in &targets {
        let (res_dir, lib_filename) = target_resource_dir(target)?;
        let src = root
            .join("target")
            .join(target)
            .join("release")
            .join(&lib_filename);
        let dst_dir = kotlin_dir.join("src/main/resources/native").join(&res_dir);
        fs::create_dir_all(&dst_dir)?;
        let dst = dst_dir.join(&lib_filename);
        fs::copy(&src, &dst)
            .with_context(|| format!("copy {} → {}", src.display(), dst.display()))?;
        println!("  Copied {} → {}", src.display(), dst.display());
    }

    // Step 5: Build JAR with Gradle.
    println!("\n--- Building JAR ---");
    let gradle = find_gradle()?;
    run_cmd(
        Command::new(&gradle).arg("jar").current_dir(&kotlin_dir),
        "gradle jar",
    )?;

    let jar_path = kotlin_dir.join("build/libs/outbe-sra-integration-0.1.0.jar");
    if jar_path.exists() {
        let size = fs::metadata(&jar_path).map(|m| m.len()).unwrap_or(0);
        println!(
            "\nKotlin JAR built: {} ({} KB)",
            jar_path.display(),
            size / 1024
        );
    } else {
        println!(
            "\nJAR built. Check {}/build/libs/ for output.",
            kotlin_dir.display()
        );
    }

    Ok(())
}

// -- Helpers --

fn run_cmd(cmd: &mut Command, description: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to run: {description}"))?;
    if !status.success() {
        bail!("{description} failed (exit code: {:?})", status.code());
    }
    Ok(())
}

fn host_target() -> Result<String> {
    let output = Command::new("rustc")
        .args(["--version", "--verbose"])
        .output()
        .context("failed to run rustc")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(target) = line.strip_prefix("host: ") {
            return Ok(target.trim().to_string());
        }
    }
    bail!("could not determine host target from rustc output")
}

fn native_lib_filename(target: &str) -> String {
    if target.contains("apple") || target.contains("darwin") {
        "liboutbe_sra_integration.dylib".to_string()
    } else {
        "liboutbe_sra_integration.so".to_string()
    }
}

fn target_resource_dir(target: &str) -> Result<(String, String)> {
    match target {
        "aarch64-apple-darwin" => Ok((
            "darwin-aarch64".to_string(),
            "liboutbe_sra_integration.dylib".to_string(),
        )),
        "x86_64-unknown-linux-gnu" => Ok((
            "linux-x86-64".to_string(),
            "liboutbe_sra_integration.so".to_string(),
        )),
        other => bail!(
            "unsupported target: {other}. Supported: aarch64-apple-darwin, x86_64-unknown-linux-gnu"
        ),
    }
}

fn find_nargo() -> Result<PathBuf> {
    // Check common locations.
    let home = env::var("HOME").unwrap_or_default();
    let nargo_home = Path::new(&home).join(".nargo/bin/nargo");

    if nargo_home.exists() {
        return Ok(nargo_home);
    }

    // Fall back to PATH.
    which_in_path("nargo")
}

fn find_gradle() -> Result<PathBuf> {
    which_in_path("gradle").context(
        "gradle not found. Install it: https://gradle.org/install/ \
         or use SDKMAN: sdk install gradle",
    )
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
        Tasks::BuildMobile { target, dev_tools } => build_mobile(&target, dev_tools),
        Tasks::BuildKotlin { targets } => build_kotlin(&targets),
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
