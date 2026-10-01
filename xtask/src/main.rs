//! `cargo xtask` — canonical-circuit tooling.
//!
//! `test-circuits` runs every vendored Noir package through `nargo test`.
//!
//! `freeze-circuits` compiles the head Noir sources under
//! `outbe-zk-canonical/noir/` and, for each circuit whose ACIR or ABI changed, mints a
//! new frozen version under `outbe-zk-canonical/resources/circuits/<module>/<version>/`
//! and records it (status `active`) in `circuits/manifest.toml`. Without
//! `--check`, it is the only command that writes frozen artifacts.
//! `--check` uses the pinned toolchain to reproduce ACIR, ABI and VK in a
//! scratch tree under `target/`, without modifying the committed files.
//!
//! When a new version supersedes the previously-active one, the old entry is set
//! to `deprecated`, its `circuit_hash` is written into the manifest (preserving
//! its identity), and its `bytecode.b64` + `abi.json` are deleted — keeping only
//! `circuit.vk`, since verification needs only the VK (a retired prover ships its
//! own bytecode).
//!
//! Version bump: unchanged ACIR and ABI are skipped; changed ACIR with the same ABI
//! is a patch bump; an ABI change requires `--abi-change` (minor) or `--semantic`
//! (major) so the layout/DOMAIN decision is explicit. `cargo build` never runs
//! this — it reads the frozen artifacts read-only.

// `xtask` is a CLI binary; stdout/stderr is its interface.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use tiny_keccak::{Hasher, Keccak};
use toml_edit::{value, DocumentMut, Table};

/// Vendored noir bin circuits: (package dir under `noir/`, nargo package name).
const CIRCUITS: &[(&str, &str)] = &[
    ("outbe-ownership-circuit", "ownership_proof"),
    ("demo-tribute", "demo_tribute"),
    ("outbe-emit-mint-circuit", "emit_mint"),
    ("outbe-paynote-circuit", "paynote"),
    ("outbe-pledge-issue-circuit", "pledge_issue"),
    ("outbe-pledge-unpledge-circuit", "pledge_unpledge"),
    ("outbe-paynote-merge-circuit", "paynote_merge"),
    ("niflheim-tribute", "niflheim_tribute"),
];

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("freeze-circuits") => {
            if let Err(error) = freeze(&args.collect::<Vec<_>>()) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        Some("test-circuits") => test_circuits(),
        other => {
            eprintln!("unknown command {other:?}");
            eprintln!("usage:");
            eprintln!("  cargo xtask freeze-circuits [--check | --abi-change | --semantic]");
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
    let packages = [
        ("outbe-circuit-core", "outbe_circuit_core"),
        ("outbe-paynote-lib", "paynote_lib"),
        ("outbe-pledge-lib", "pledge_lib"),
    ]
    .into_iter()
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

fn freeze(flags: &[String]) -> Result<(), Box<dyn Error>> {
    if flags.len() > 1
        || flags
            .iter()
            .any(|flag| !matches!(flag.as_str(), "--check" | "--abi-change" | "--semantic"))
    {
        return Err(
            "usage: cargo xtask freeze-circuits [--check | --abi-change | --semantic]".into(),
        );
    }
    let check = flags.iter().any(|f| f == "--check");
    let semantic = flags.iter().any(|f| f == "--semantic");
    let abi_change = flags.iter().any(|f| f == "--abi-change");

    let root = workspace_root();
    let canonical = root.join("crates").join("outbe-zk-canonical");
    let noir = canonical.join("noir");
    let resources = canonical.join("resources/circuits");
    let manifest_path = canonical.join("circuits/manifest.toml");

    let nargo = locate("NARGO", ".nargo/bin/nargo", "nargo").expect("nargo not found (set $NARGO)");
    let bb = locate("BB", ".bb/bb", "bb").expect("bb not found (set $BB)");
    if check {
        assert_pinned(&root, &nargo, &bb)?;
    }

    // Copy the entire tree so relative dependencies still resolve. The guard
    // is live before copying or compiling, including on errors and panics.
    let scratch = if check {
        Some(Scratch::new(&root.join("target"))?)
    } else {
        None
    };
    let noir = if let Some(scratch) = &scratch {
        let copy = scratch.0.join("noir");
        copy_noir(&noir, &copy)?;
        copy
    } else {
        noir
    };

    let mut doc: DocumentMut = std::fs::read_to_string(&manifest_path)
        .expect("read manifest.toml")
        .parse()
        .expect("parse manifest.toml");

    let mut minted = 0usize;
    let mut failures = Vec::new();
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

        if let Some(scratch) = &scratch {
            match active {
                Some((_, ver)) => {
                    // Always derive the VK, even when ACIR and ABI match.
                    let result = write_vk(&bb, &json_path, &scratch.0.join(".bb").join(module))
                        .and_then(|path| {
                            check_version(
                                &resources.join(module).join(&ver),
                                &new_hash,
                                &json["abi"],
                                &std::fs::read(path)?,
                            )
                        });
                    match result {
                        Ok(()) => println!("  reproduces {module} @ {ver}"),
                        Err(error) => failures.push(format!("{module} @ {ver}: {error}")),
                    }
                }
                None => failures.push(format!("{module}: no active frozen version")),
            }
            continue;
        }

        let (new_version, supersede) = match &active {
            Some((idx, ver)) => {
                let dir_v = resources.join(module).join(ver);
                let cur_b64 =
                    std::fs::read_to_string(dir_v.join("bytecode.b64")).expect("active bytecode");
                let cur_acir = base64::engine::general_purpose::STANDARD
                    .decode(cur_b64.trim())
                    .expect("active base64");
                let cur_hash = keccak_hex(&cur_acir);
                // Semantic ABI compare (structural, key-order/format-insensitive)
                // — a raw-string compare would false-positive on serializer
                // differences (jq vs serde_json).
                let cur_abi: Option<serde_json::Value> =
                    std::fs::read_to_string(dir_v.join("abi.json"))
                        .ok()
                        .and_then(|s| serde_json::from_str(&s).ok());
                let abi_differs = cur_abi.as_ref() != Some(&json["abi"]);
                if cur_hash == new_hash && !abi_differs {
                    println!("  unchanged  {module} @ {ver}");
                    continue;
                }
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

    // Return before any manifest writes or retired-artifact reconciliation.
    // Returning also drops the scratch guard before main reports an error.
    if check {
        if !failures.is_empty() {
            return Err(failures.join("\n").into());
        }
        println!("\nall active circuits reproduce.");
        return Ok(());
    }

    reconcile_artifacts(&mut doc, &resources);

    std::fs::write(&manifest_path, doc.to_string()).expect("write manifest.toml");
    println!("\n{minted} circuit(s) minted.");
    Ok(())
}

/// A check owns only this newly created, per-process scratch directory.
struct Scratch(PathBuf);

impl Scratch {
    fn new(parent: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(parent)?;
        let path = parent.join(format!("xtask-freeze-check-{}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn copy_noir(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "target" {
            continue;
        }
        let to = dst.join(name);
        if entry.file_type()?.is_dir() {
            copy_noir(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), to)?;
        }
    }
    Ok(())
}

fn assert_pinned(root: &Path, nargo: &Path, bb: &Path) -> Result<(), Box<dyn Error>> {
    let doc: DocumentMut = std::fs::read_to_string(root.join("mise.toml"))?.parse()?;
    for (tool, bin) in [("nargo", nargo), ("bb", bb)] {
        let pin = doc
            .get("tools")
            .and_then(|tools| tools.get(tool))
            .and_then(|tool| tool.get("version"))
            .and_then(toml_edit::Item::as_str)
            .ok_or_else(|| format!("mise.toml: missing tools.{tool}.version"))?;
        let output = Command::new(bin).arg("--version").output()?;
        if !output.status.success() {
            return Err(format!("{} --version failed: {}", bin.display(), output.status).into());
        }
        let stdout = String::from_utf8(output.stdout)?;
        let first = stdout.lines().next().unwrap_or("").trim();
        let version = if tool == "nargo" {
            first.strip_prefix("nargo version = ").unwrap_or(first)
        } else {
            first
        };
        if version != pin {
            return Err(format!(
                "{} --version reports {first:?}; mise.toml pins {tool} {pin}",
                bin.display()
            )
            .into());
        }
    }
    Ok(())
}

fn check_version(
    dir: &Path,
    acir_hash: &str,
    abi: &serde_json::Value,
    vk: &[u8],
) -> Result<(), Box<dyn Error>> {
    let b64 = std::fs::read_to_string(dir.join("bytecode.b64"))?;
    let acir = base64::engine::general_purpose::STANDARD.decode(b64.trim())?;
    let frozen_hash = keccak_hex(&acir);
    if frozen_hash != acir_hash {
        return Err(format!(
            "bytecode.b64 does not reproduce: committed {frozen_hash}, compiled {acir_hash}"
        )
        .into());
    }
    let frozen_abi: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("abi.json"))?)?;
    if &frozen_abi != abi {
        return Err("abi.json does not match the compiled ABI".into());
    }
    let frozen_vk = std::fs::read(dir.join("circuit.vk"))?;
    if frozen_vk != vk {
        return Err(format!(
            "circuit.vk does not reproduce: committed {}, derived {}",
            keccak_hex(&frozen_vk),
            keccak_hex(vk)
        )
        .into());
    }
    Ok(())
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
    let produced =
        write_vk(bb, json_path, &tmp).unwrap_or_else(|error| panic!("{module}: {error}"));
    std::fs::rename(&produced, dir.join("circuit.vk")).expect("install circuit.vk");
    let _ = std::fs::remove_dir_all(&tmp);
}

fn write_vk(bb: &Path, json_path: &Path, output: &Path) -> Result<PathBuf, Box<dyn Error>> {
    std::fs::create_dir_all(output)?;
    let status = Command::new(bb)
        .arg("write_vk")
        .arg("-b")
        .arg(json_path)
        .arg("-o")
        .arg(output)
        .args(["-t", "evm-no-zk"])
        .status()?;
    if !status.success() {
        return Err(format!("bb write_vk failed for {}: {status}", json_path.display()).into());
    }
    Ok(output.join("vk"))
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
        "demo_tribute" => "demo.tribute".to_string(),
        "emit_mint" => "outbe.emit.mint".to_string(),
        "paynote" => "outbe.paynote".to_string(),
        "pledge_issue" => "outbe.pledge.issue".to_string(),
        "pledge_unpledge" => "outbe.pledge.unpledge".to_string(),
        "paynote_merge" => "outbe.paynote.merge".to_string(),
        "niflheim_tribute" => "niflheim.tribute".to_string(),
        _ => panic!("unknown module: {module}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_check_rejects_each_artifact_drifting() {
        let scratch = Scratch::new(&std::env::temp_dir()).unwrap();
        let dir = &scratch.0;
        let acir = b"compiled ACIR";
        let hash = keccak_hex(acir);
        let abi = serde_json::json!({"parameters": [], "return_type": null});
        let vk = b"derived VK";
        std::fs::write(
            dir.join("bytecode.b64"),
            format!(
                "{}\n",
                base64::engine::general_purpose::STANDARD.encode(acir)
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("abi.json"),
            "{\n  \"return_type\": null,\n  \"parameters\": []\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("circuit.vk"), vk).unwrap();

        // Base64 whitespace and JSON formatting/order are not circuit drift.
        assert!(check_version(dir, &hash, &abi, vk).is_ok());
        assert!(check_version(dir, &keccak_hex(b"changed ACIR"), &abi, vk).is_err());
        let changed_abi = serde_json::json!({"parameters": [{"name": "new_input"}]});
        assert!(check_version(dir, &hash, &changed_abi, vk).is_err());
        // An unchanged ACIR and ABI must never hide a stale verification key.
        assert!(check_version(dir, &hash, &abi, b"different VK").is_err());
        std::fs::remove_file(dir.join("circuit.vk")).unwrap();
        assert!(check_version(dir, &hash, &abi, vk).is_err());
    }
}
