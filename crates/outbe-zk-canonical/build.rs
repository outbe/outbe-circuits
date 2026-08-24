//! Build script for `outbe-zk-canonical` — **read-only** codegen over a frozen,
//! versioned circuit registry. It does NOT run `nargo`/`bb`; compiling a circuit
//! is a deliberate release step (`cargo xtask freeze-circuits`) that mints frozen
//! artifacts. This script just reads them.
//!
//! Inputs:
//!   * `circuits/manifest.toml` — the append-only registry index: one entry per
//!     `(module, version)` with `label` + `status` (+ `circuit_hash` once the
//!     bytecode has been dropped), and a global `proof_system`.
//!   * `resources/circuits/<module>/<version>/` — frozen artifacts:
//!       - `circuit.vk`     — always present (verification needs only the VK);
//!       - `bytecode.b64`   — only for the **active** version (proving artifact);
//!       - `abi.json`       — only for the active version (drives the Rust types).
//!
//! Output (`$OUT_DIR/noir_generated.rs`):
//!   * `pub mod <module> { … }` for the **latest active** version of each module
//!     — witness / public-input types + identity consts + `Circuit<S>` /
//!     `CircuitId` impls (the prover-facing API; carries `BYTECODE_B64`).
//!   * `pub const CIRCUIT_REGISTRY: &[crate::RegistryEntry]` over **every** entry
//!     (all versions) — the verification view (VK only, no bytecode).

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

use base64::Engine;
use serde_json::Value;
use tiny_keccak::{Hasher, Keccak};

/// One manifest entry + its computed identity. `abi`/bytecode are present only
/// for provable (active) versions; deprecated versions keep just the VK.
struct Loaded {
    module: String,
    label: String,
    version: String,
    status: String,
    circuit_hash: [u8; 32],
    vk_hash: [u8; 32],
    abi: Option<Value>,
    has_bytecode: bool,
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_path = manifest_dir.join("circuits/manifest.toml");
    println!("cargo:rerun-if-changed={}", manifest_path.display());

    let manifest: toml::Value = toml::from_str(
        &fs::read_to_string(&manifest_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display())),
    )
    .unwrap_or_else(|e| panic!("parse {}: {e}", manifest_path.display()));

    let proof_system = manifest["proof_system"]
        .as_str()
        .expect("manifest: proof_system must be a string")
        .to_string();
    let circuits = manifest["circuit"]
        .as_array()
        .expect("manifest: [[circuit]] array required");

    let mut loaded: Vec<Loaded> = Vec::new();
    for c in circuits {
        let module = c["module"].as_str().expect("circuit.module").to_string();
        let label = c["label"].as_str().expect("circuit.label").to_string();
        let version = c["version"].as_str().expect("circuit.version").to_string();
        let status = c["status"].as_str().expect("circuit.status").to_string();
        let manifest_hash = c.get("circuit_hash").and_then(|v| v.as_str());

        // Revoked = obsolete: its VK has been dropped, so it can't be a registry
        // entry (verification needs the VK). The manifest keeps the record.
        if status == "revoked" {
            continue;
        }

        let dir = manifest_dir.join(format!("resources/circuits/{module}/{version}"));
        let vk_path = dir.join("circuit.vk");
        let b64_path = dir.join("bytecode.b64");
        let abi_path = dir.join("abi.json");
        println!("cargo:rerun-if-changed={}", vk_path.display());
        println!("cargo:rerun-if-changed={}", b64_path.display());
        println!("cargo:rerun-if-changed={}", abi_path.display());

        // VK is always present — verification needs only it.
        let vk = fs::read(&vk_path).unwrap_or_else(|e| panic!("read {}: {e}", vk_path.display()));
        let vk_hash = keccak256(&vk);

        // Bytecode is kept only for the active version. If absent, the identity
        // is preserved in the manifest's `circuit_hash`.
        let has_bytecode = b64_path.exists();
        let circuit_hash = if has_bytecode {
            let bytecode = fs::read_to_string(&b64_path)
                .unwrap_or_else(|e| panic!("read {}: {e}", b64_path.display()));
            let acir = base64::engine::general_purpose::STANDARD
                .decode(bytecode.trim())
                .unwrap_or_else(|e| panic!("{module}@{version}: bad base64: {e}"));
            keccak256(&acir)
        } else {
            hex_to_32(manifest_hash.unwrap_or_else(|| {
                panic!("{module}@{version}: bytecode dropped but manifest has no circuit_hash")
            }))
        };

        let abi = if abi_path.exists() {
            Some(
                serde_json::from_str(
                    &fs::read_to_string(&abi_path)
                        .unwrap_or_else(|e| panic!("read {}: {e}", abi_path.display())),
                )
                .unwrap_or_else(|e| panic!("parse {}: {e}", abi_path.display())),
            )
        } else {
            None
        };

        loaded.push(Loaded {
            module,
            label,
            version,
            status,
            circuit_hash,
            vk_hash,
            abi,
            has_bytecode,
        });
    }

    let mut generated = String::new();
    generated.push_str("// @generated by build.rs from the frozen circuit registry.\n");
    generated.push_str(
        "// Source of truth: circuits/manifest.toml + resources/circuits/<module>/<version>/.\n",
    );
    generated.push_str("use ark_bn254::Fr;\n\n");
    generated.push_str("#[derive(Clone, Copy, Debug)]\n");
    generated.push_str("pub struct EmbeddedCurvePoint {\n    pub x: Fr,\n    pub y: Fr,\n}\n\n");

    // Per module, the latest **active** version that is provable (has bytecode +
    // ABI) is the prover-facing "head".
    let mut head: BTreeMap<&str, &Loaded> = BTreeMap::new();
    for l in &loaded {
        if l.status != "active" || l.abi.is_none() || !l.has_bytecode {
            continue;
        }
        head.entry(&l.module)
            .and_modify(|cur| {
                if version_key(&l.version) > version_key(&cur.version) {
                    *cur = l;
                }
            })
            .or_insert(l);
    }
    for l in head.values() {
        generated.push_str(&gen_module(l));
    }

    // The in-code registry over every entry (all versions). VK-only view.
    let mut registry = String::from(
        "/// Append-only registry of every frozen circuit version (see `circuits/manifest.toml`).\n\
         pub const CIRCUIT_REGISTRY: &[crate::RegistryEntry] = &[\n",
    );
    for l in &loaded {
        registry.push_str(&gen_registry_entry(l, &proof_system));
    }
    registry.push_str("];\n");
    generated.push_str(&registry);

    fs::write(out_dir.join("noir_generated.rs"), generated)
        .expect("failed to write noir_generated.rs");
}

/// keccak256 (Ethereum variant), used for both `circuit_hash` and `vk_hash`.
fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// Parse a `"a.b.c"` semver into a comparable tuple (missing parts = 0).
fn version_key(v: &str) -> (u64, u64, u64) {
    let mut it = v.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// 64-char (optionally `0x`-prefixed) hex string -> `[u8; 32]`.
fn hex_to_32(s: &str) -> [u8; 32] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert_eq!(
        s.len(),
        64,
        "circuit_hash must be 64 hex chars, got {}",
        s.len()
    );
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("valid hex");
    }
    out
}

/// Lower-case hex of a digest (no `0x`).
fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A `hex!("..")` literal (`hex-literal` crate) for a 32-byte digest — readable,
/// compile-time, `[u8; 32]`.
fn hex_lit(bytes: &[u8; 32]) -> String {
    format!("::hex_literal::hex!({:?})", hex_str(bytes))
}

/// Marker (unit) type name: `flat_aggregation_n2` -> `FlatAggregationN2`.
fn marker_ident(module: &str) -> String {
    module
        .split('_')
        .map(|seg| {
            let mut c = seg.chars();
            match c.next() {
                Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// One `crate::RegistryEntry { … }` literal (verification view: VK only).
fn gen_registry_entry(l: &Loaded, proof_system: &str) -> String {
    let status = match l.status.as_str() {
        "active" => "Active",
        "deprecated" => "Deprecated",
        "revoked" => "Revoked",
        other => panic!("{}: unknown status {other:?}", l.module),
    };
    let (m, v) = (&l.module, &l.version);
    format!(
        "    crate::RegistryEntry {{\n\
         \x20       label: {label:?},\n\
         \x20       version: {v:?},\n\
         \x20       status: crate::CircuitStatus::{status},\n\
         \x20       proof_system: {proof_system:?},\n\
         \x20       circuit_hash: {ch},\n\
         \x20       vk_hash: {vh},\n\
         \x20       vk_bytes: include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/resources/circuits/{m}/{v}/circuit.vk\")),\n\
         \x20   }},\n",
        label = l.label,
        ch = hex_lit(&l.circuit_hash),
        vh = hex_lit(&l.vk_hash),
    )
}

/// Generate `pub mod <module> { … }` for the head (latest active) version.
fn gen_module(l: &Loaded) -> String {
    let module = &l.module;
    let version = &l.version;
    let params = l.abi.as_ref().expect("head module has ABI")["parameters"]
        .as_array()
        .unwrap_or_else(|| panic!("{module}@{version}: abi.parameters is not an array"));

    let mut witness_fields = String::new();
    let mut public_fields = String::new();
    for p in params {
        let name = p["name"].as_str().unwrap();
        let ty = rust_type(&p["type"], module);
        let line = format!("        pub {name}: {ty},\n");
        match p["visibility"].as_str() {
            Some("private") => witness_fields.push_str(&line),
            Some("public") => public_fields.push_str(&line),
            other => panic!("{module}: param {name} has unexpected visibility {other:?}"),
        }
    }

    let marker = marker_ident(module);

    let mut m = String::new();
    m.push_str(&format!("pub mod {module} {{\n"));
    // Only circuits with an embedded-curve-point param (e.g. `pk`) reference the
    // type — a circuit with no such parameter would warn on the import.
    if witness_fields.contains("EmbeddedCurvePoint") || public_fields.contains("EmbeddedCurvePoint")
    {
        m.push_str("    use super::EmbeddedCurvePoint;\n");
    }
    m.push_str("    use ark_bn254::Fr;\n\n");

    m.push_str("    /// Private (witness) inputs, in ABI order.\n");
    m.push_str("    #[derive(Clone, Debug)]\n");
    m.push_str("    pub struct Witness {\n");
    m.push_str(&witness_fields);
    m.push_str("    }\n\n");

    m.push_str("    /// Public inputs, in ABI order.\n");
    m.push_str("    #[derive(Clone, Debug)]\n");
    m.push_str("    pub struct PublicInputs {\n");
    m.push_str(&public_fields);
    m.push_str("    }\n\n");

    m.push_str("    /// Canonical dotted label (matches `outbe-zk-canonical`).\n");
    m.push_str(&format!("    pub const LABEL: &str = {:?};\n", l.label));
    m.push_str("    /// Semver-style version string. Not authoritative.\n");
    m.push_str(&format!("    pub const VERSION: &str = {version:?};\n"));
    m.push_str("    /// `keccak256(base64_decode(bytecode))` — authoritative identity.\n");
    m.push_str(&format!(
        "    pub const CIRCUIT_HASH: [u8; 32] = {};\n",
        hex_lit(&l.circuit_hash)
    ));
    m.push_str("    /// Base64-encoded ACIR bytecode (frozen; the proving artifact).\n");
    m.push_str(&format!(
        "    pub const BYTECODE_B64: &str = include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/resources/circuits/{module}/{version}/bytecode.b64\"));\n"
    ));
    m.push_str("    /// UltraHonkKeccak verification key (frozen).\n");
    m.push_str(&format!(
        "    pub const VK_BYTES: &[u8] = include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/resources/circuits/{module}/{version}/circuit.vk\"));\n"
    ));
    m.push_str("    /// `keccak256(VK_BYTES)`.\n");
    m.push_str(&format!(
        "    pub const VK_HASH: [u8; 32] = {};\n\n",
        hex_lit(&l.vk_hash)
    ));

    m.push_str(&format!(
        "    /// Canonical marker type for the `{}` circuit.\n",
        l.label
    ));
    m.push_str(&format!("    pub struct {marker};\n\n"));

    let mut flatten = String::from("            let mut v: Vec<S::Field> = Vec::new();\n");
    for p in params {
        if p["visibility"].as_str() != Some("public") {
            continue;
        }
        let name = p["name"].as_str().unwrap();
        emit_abi_leaf(
            &p["type"],
            &format!("p.{name}"),
            &mut flatten,
            "            ",
            0,
        );
    }
    flatten.push_str("            v\n");

    let mut abi_flat = String::from("            let mut v: Vec<S::Field> = Vec::new();\n");
    for p in params {
        let name = p["name"].as_str().unwrap();
        let src = match p["visibility"].as_str() {
            Some("private") => "w",
            Some("public") => "p",
            other => panic!("{module}: param {name} has unexpected visibility {other:?}"),
        };
        emit_abi_leaf(
            &p["type"],
            &format!("{src}.{name}"),
            &mut abi_flat,
            "            ",
            0,
        );
    }
    abi_flat.push_str("            v\n");

    m.push_str("    impl<S: crate::CircuitSuite> outbe_protocol::protocol::zk::Circuit<S> for ");
    m.push_str(&format!("{marker} {{\n"));
    m.push_str("        type Witness = Witness;\n");
    m.push_str("        type PublicInputs = PublicInputs;\n");
    m.push_str("        fn public_inputs(p: &PublicInputs) -> Vec<S::Field> {\n");
    m.push_str(&flatten);
    m.push_str("        }\n");
    m.push_str("        fn witness_inputs(w: &Witness, p: &PublicInputs) -> Vec<S::Field> {\n");
    m.push_str(&abi_flat);
    m.push_str("        }\n");
    m.push_str("    }\n\n");

    m.push_str(&format!("    impl crate::CircuitId for {marker} {{\n"));
    m.push_str("        const LABEL: &'static str = LABEL;\n");
    m.push_str("        const VERSION: &'static str = VERSION;\n");
    m.push_str("        const CIRCUIT_HASH: [u8; 32] = CIRCUIT_HASH;\n");
    m.push_str("        const BYTECODE_B64: &'static str = BYTECODE_B64;\n");
    m.push_str("        const VK_BYTES: &'static [u8] = VK_BYTES;\n");
    m.push_str("        const VK_HASH: [u8; 32] = VK_HASH;\n");
    m.push_str("    }\n");

    m.push_str("}\n\n");
    m
}

/// Flatten one ABI parameter into the running `Vec<S::Field> v` in ABI order.
fn emit_abi_leaf(ty: &Value, expr: &str, out: &mut String, indent: &str, depth: usize) {
    match ty["kind"].as_str() {
        Some("field") => out.push_str(&format!("{indent}v.push({expr});\n")),
        Some("integer") => {
            out.push_str(&format!("{indent}v.push(S::Field::from({expr} as u64));\n"))
        }
        Some("boolean") => {
            out.push_str(&format!("{indent}v.push(S::Field::from({expr} as u64));\n"))
        }
        Some("array") => {
            let var = format!("__e{depth}");
            out.push_str(&format!("{indent}for {var} in {expr}.iter().copied() {{\n"));
            emit_abi_leaf(&ty["type"], &var, out, &format!("{indent}    "), depth + 1);
            out.push_str(&format!("{indent}}}\n"));
        }
        Some("struct") => {
            out.push_str(&format!("{indent}v.push({expr}.x);\n"));
            out.push_str(&format!("{indent}v.push({expr}.y);\n"));
        }
        other => panic!("witness_inputs: unsupported ABI kind {other:?}"),
    }
}

/// Map a noir ABI type to a Rust type string.
fn rust_type(ty: &Value, module: &str) -> String {
    match ty["kind"].as_str() {
        Some("field") => "Fr".to_string(),
        Some("boolean") => "bool".to_string(),
        Some("integer") => {
            let sign = ty["sign"].as_str().unwrap_or("unsigned");
            let width = ty["width"].as_u64().expect("integer width");
            match sign {
                "unsigned" => format!("u{width}"),
                "signed" => format!("i{width}"),
                other => panic!("{module}: unexpected integer sign {other}"),
            }
        }
        Some("array") => {
            let len = ty["length"].as_u64().expect("array length");
            let inner = rust_type(&ty["type"], module);
            format!("[{inner}; {len}]")
        }
        Some("struct") => {
            let path = ty["path"].as_str().unwrap_or("");
            if path == "std::embedded_curve_ops::EmbeddedCurvePoint" {
                "EmbeddedCurvePoint".to_string()
            } else {
                panic!("{module}: unsupported struct ABI type {path}");
            }
        }
        other => panic!("{module}: unsupported ABI kind {other:?}"),
    }
}
