//! `cargo xtask` — canonical-circuit tooling.
//!
//! `test-circuits` runs every vendored Noir package through `nargo test`.
//!
//! `freeze-circuits` compiles the head Noir sources under
//! `outbe-zk-canonical/noir/` and, for each circuit whose ACIR changed, mints a
//! new frozen version under `outbe-zk-canonical/resources/circuits/<module>/<version>/`
//! and records it (status `active`) in `circuits/manifest.toml`. It is the only
//! command that invokes `bb` or writes frozen artifacts.
//!
//! When a new version supersedes the previously-active one, the old entry is set
//! to `deprecated`, its `circuit_hash` is written into the manifest (preserving
//! its identity), and its `bytecode.b64` + `abi.json` are deleted — keeping only
//! `circuit.vk`, since verification needs only the VK (a retired prover ships its
//! own bytecode).
//!
//! Version bump: an unchanged ACIR is skipped; a changed ACIR with the same ABI
//! is a patch bump; an ABI change requires `--abi-change` (minor) or `--semantic`
//! (major) so the layout/DOMAIN decision is explicit. `cargo build` never runs
//! this — it reads the frozen artifacts read-only.

// `xtask` is a CLI binary; stdout/stderr is its interface.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use tiny_keccak::{Hasher, Keccak};
use toml_edit::{value, DocumentMut, Table};

/// Vendored noir bin circuits: (package dir under `noir/`, nargo package name).
const CIRCUITS: &[(&str, &str)] = &[
    ("outbe-ownership-circuit", "ownership_proof"),
    ("outbe-flat-aggregation-circuit-n1", "flat_aggregation_n1"),
    ("outbe-flat-aggregation-circuit-n2", "flat_aggregation_n2"),
    ("outbe-flat-aggregation-circuit-n4", "flat_aggregation_n4"),
    ("outbe-flat-aggregation-circuit-n8", "flat_aggregation_n8"),
    ("outbe-flat-aggregation-circuit-n16", "flat_aggregation_n16"),
    ("outbe-flat-aggregation-circuit-n32", "flat_aggregation_n32"),
    ("outbe-flat-aggregation-circuit-n64", "flat_aggregation_n64"),
    ("outbe-full-circuit", "full_proof"),
    ("outbe-emit-mint-circuit", "emit_mint"),
];

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("freeze-circuits") => freeze(&args.collect::<Vec<_>>()),
        Some("test-circuits") => test_circuits(),
        other => {
            eprintln!("unknown command {other:?}");
            eprintln!("usage:");
            eprintln!("  cargo xtask freeze-circuits [--abi-change | --semantic]");
            eprintln!("  cargo xtask test-circuits");
            std::process::exit(2);
        }
    }
}

fn test_circuits() {
    let noir = workspace_root()
        .join("crates")
        .join("outbe-zk-canonical")
        .join("noir");
    let nargo = locate("NARGO", ".nargo/bin/nargo", "nargo").expect("nargo not found (set $NARGO)");
    let packages = std::iter::once(("outbe-circuit-core", "outbe_circuit_core"))
        .chain(CIRCUITS.iter().copied());

    let mut tested = 0usize;
    for (dir, package) in packages {
        println!("  testing    {package}");
        let status = Command::new(&nargo)
            .arg("test")
            .current_dir(noir.join(dir))
            .status()
            .unwrap_or_else(|e| panic!("spawn nargo for {dir}: {e}"));
        if !status.success() {
            eprintln!("nargo test failed for {dir}");
            std::process::exit(status.code().unwrap_or(1));
        }
        tested += 1;
    }

    println!("\n{tested} Noir package(s) tested.");
}

fn freeze(flags: &[String]) {
    let semantic = flags.iter().any(|f| f == "--semantic");
    let abi_change = flags.iter().any(|f| f == "--abi-change");

    let root = workspace_root();
    let canonical = root.join("crates").join("outbe-zk-canonical");
    let noir = canonical.join("noir");
    let resources = canonical.join("resources/circuits");
    let manifest_path = canonical.join("circuits/manifest.toml");

    let nargo = locate("NARGO", ".nargo/bin/nargo", "nargo").expect("nargo not found (set $NARGO)");
    let bb = locate("BB", ".bb/bb", "bb").expect("bb not found (set $BB)");

    let mut doc: DocumentMut = std::fs::read_to_string(&manifest_path)
        .expect("read manifest.toml")
        .parse()
        .expect("parse manifest.toml");

    let mut minted = 0usize;
    for (dir, module) in CIRCUITS {
        let pkg = noir.join(dir);
        let st = Command::new(&nargo)
            .arg("compile")
            .current_dir(&pkg)
            .status()
            .unwrap_or_else(|e| panic!("spawn nargo for {dir}: {e}"));
        assert!(st.success(), "nargo compile failed for {dir}");

        let json_path = pkg.join("target").join(format!("{module}.json"));
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_path).expect("read circuit json"))
                .expect("parse circuit json");
        let bytecode = json["bytecode"].as_str().expect("bytecode").to_string();
        let abi_str = serde_json::to_string(&json["abi"]).expect("serialize abi");
        let acir = base64::engine::general_purpose::STANDARD
            .decode(&bytecode)
            .expect("base64");
        let new_hash = keccak_hex(&acir);

        // The module's current active version, if any.
        let aot = doc["circuit"]
            .as_array_of_tables()
            .expect("[[circuit]] array");
        let active = (0..aot.len()).find_map(|i| {
            let t = aot.get(i).unwrap();
            (t["module"].as_str() == Some(*module) && t["status"].as_str() == Some("active"))
                .then(|| (i, t["version"].as_str().unwrap().to_string()))
        });

        let (new_version, supersede) = match &active {
            Some((idx, ver)) => {
                let dir_v = resources.join(module).join(ver);
                let cur_b64 =
                    std::fs::read_to_string(dir_v.join("bytecode.b64")).expect("active bytecode");
                let cur_acir = base64::engine::general_purpose::STANDARD
                    .decode(cur_b64.trim())
                    .expect("active base64");
                let cur_hash = keccak_hex(&cur_acir);
                if cur_hash == new_hash {
                    println!("  unchanged  {module} @ {ver}");
                    continue;
                }
                // Semantic ABI compare (structural, key-order/format-insensitive)
                // — a raw-string compare would false-positive on serializer
                // differences (jq vs serde_json).
                let cur_abi: Option<serde_json::Value> =
                    std::fs::read_to_string(dir_v.join("abi.json"))
                        .ok()
                        .and_then(|s| serde_json::from_str(&s).ok());
                let abi_differs = cur_abi.as_ref() != Some(&json["abi"]);
                let nv = if abi_differs {
                    if semantic {
                        bump(ver, 0)
                    } else if abi_change {
                        bump(ver, 1)
                    } else {
                        panic!("{module}: ABI changed — pass --abi-change (minor) or --semantic (major)");
                    }
                } else {
                    bump(ver, 2)
                };
                (nv, Some((*idx, ver.clone(), cur_hash)))
            }
            None => ("1.0.0".to_string(), None),
        };

        write_version(
            &resources,
            module,
            &new_version,
            &bytecode,
            &abi_str,
            &bb,
            &json_path,
        );

        // Append the new active entry (bytecode present -> build.rs derives the hash).
        let mut t = Table::new();
        t["module"] = value(*module);
        t["label"] = value(label(module));
        t["version"] = value(new_version.clone());
        t["status"] = value("active");
        doc["circuit"].as_array_of_tables_mut().unwrap().push(t);

        match supersede {
            Some((idx, ver, hash)) => {
                // Deprecate the old version + preserve its identity. The artifact
                // drop happens in the reconcile pass below.
                let old = doc["circuit"]
                    .as_array_of_tables_mut()
                    .unwrap()
                    .get_mut(idx)
                    .unwrap();
                old["status"] = value("deprecated");
                old["circuit_hash"] = value(hash);
                println!("  minted     {module} {ver} -> {new_version}  (old -> deprecated)");
            }
            None => println!("  minted     {module} @ {new_version}  (new)"),
        }
        minted += 1;
    }

    reconcile_artifacts(&mut doc, &resources);

    std::fs::write(&manifest_path, doc.to_string()).expect("write manifest.toml");
    println!("\n{minted} circuit(s) minted.");
}

/// Enforce the on-disk artifacts of every entry to match its status (idempotent;
/// also applies to statuses hand-edited into the manifest):
///   * `active`     — bytecode + abi + vk (kept);
///   * `deprecated` — vk only (bytecode + abi dropped; still verifies);
///   * `revoked`    — nothing (vk dropped too; the version dir removed).
///
/// Before deleting anything it preserves the binary identity in the manifest
/// (`circuit_hash`) if not already recorded — covering a direct active→revoked
/// edit where the bytecode is still present.
fn reconcile_artifacts(doc: &mut DocumentMut, resources: &Path) {
    let n = doc["circuit"].as_array_of_tables().unwrap().len();
    for i in 0..n {
        let (module, version, status, has_hash) = {
            let t = doc["circuit"].as_array_of_tables().unwrap().get(i).unwrap();
            (
                t["module"].as_str().unwrap().to_string(),
                t["version"].as_str().unwrap().to_string(),
                t["status"].as_str().unwrap().to_string(),
                t.get("circuit_hash").is_some(),
            )
        };
        if status == "active" {
            continue;
        }
        let dir = resources.join(&module).join(&version);

        if !has_hash {
            if let Ok(b64) = std::fs::read_to_string(dir.join("bytecode.b64")) {
                if let Ok(acir) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                    let hash = keccak_hex(&acir);
                    doc["circuit"]
                        .as_array_of_tables_mut()
                        .unwrap()
                        .get_mut(i)
                        .unwrap()["circuit_hash"] = value(hash);
                }
            }
        }

        let _ = std::fs::remove_file(dir.join("bytecode.b64"));
        let _ = std::fs::remove_file(dir.join("abi.json"));
        if status == "revoked" {
            let _ = std::fs::remove_file(dir.join("circuit.vk"));
            let _ = std::fs::remove_dir(&dir); // succeeds only if now empty
        }
    }
}

/// Write a frozen version dir: `bytecode.b64`, `abi.json`, and `circuit.vk`
/// (derived via `bb write_vk -t evm-no-zk`).
fn write_version(
    resources: &Path,
    module: &str,
    version: &str,
    bytecode_b64: &str,
    abi_str: &str,
    bb: &Path,
    json_path: &Path,
) {
    let dir = resources.join(module).join(version);
    std::fs::create_dir_all(&dir).expect("mkdir version dir");
    std::fs::write(dir.join("bytecode.b64"), bytecode_b64).expect("write bytecode.b64");
    std::fs::write(dir.join("abi.json"), abi_str).expect("write abi.json");

    let tmp = dir.join(".bb");
    std::fs::create_dir_all(&tmp).expect("mkdir bb tmp");
    let st = Command::new(bb)
        .arg("write_vk")
        .arg("-b")
        .arg(json_path)
        .arg("-o")
        .arg(&tmp)
        .args(["-t", "evm-no-zk"])
        .status()
        .unwrap_or_else(|e| panic!("spawn bb for {module}: {e}"));
    assert!(st.success(), "bb write_vk failed for {module}");
    let produced = tmp.join("vk");
    assert!(produced.exists(), "bb produced no vk for {module}");
    std::fs::rename(&produced, dir.join("circuit.vk")).expect("install circuit.vk");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// keccak256 -> lower-case hex (no `0x`).
fn keccak_hex(bytes: &[u8]) -> String {
    let mut h = Keccak::v256();
    h.update(bytes);
    let mut o = [0u8; 32];
    h.finalize(&mut o);
    o.iter().map(|b| format!("{b:02x}")).collect()
}

/// Bump a `"a.b.c"` semver: level 0 = major, 1 = minor, 2 = patch.
fn bump(ver: &str, level: u8) -> String {
    let mut p: Vec<u64> = ver.split('.').map(|x| x.parse().unwrap_or(0)).collect();
    while p.len() < 3 {
        p.push(0);
    }
    match level {
        0 => {
            p[0] += 1;
            p[1] = 0;
            p[2] = 0;
        }
        1 => {
            p[1] += 1;
            p[2] = 0;
        }
        _ => p[2] += 1,
    }
    format!("{}.{}.{}", p[0], p[1], p[2])
}

/// Canonical dotted label for a module.
fn label(module: &str) -> String {
    match module {
        "ownership_proof" => "outbe.ownership".to_string(),
        "full_proof" => "outbe.full_proof".to_string(),
        "emit_mint" => "outbe.emit.mint".to_string(),
        m => {
            let n = m
                .strip_prefix("flat_aggregation_n")
                .expect("unknown module");
            format!("outbe.flat_aggregation.n{n}")
        }
    }
}

/// Workspace root = the xtask crate's parent directory.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Locate a tool via `$ENV`, then `$HOME/<home_rel>`, then PATH.
fn locate(env_var: &str, home_rel: &str, bin: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(env_var) {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = Path::new(&home).join(home_rel);
        if p.exists() {
            return Some(p);
        }
    }
    Command::new(bin)
        .arg("--version")
        .status()
        .ok()
        .filter(|s| s.success())
        .map(|_| PathBuf::from(bin))
}
