//! L1 circuit commands. A freeze writes only under
//! `crates/outbe-zk-canonical/`; `--check` writes only under `target/`.
//!
//! `test-circuits` runs every vendored Noir package through `nargo test`, then
//! every non-revoked L2 root (a root with no `#[test]` exits 0).
//!
//! `freeze-circuits` compiles the head Noir sources under
//! `outbe-zk-canonical/noir/` and, for each circuit whose ACIR or ABI changed,
//! mints a new frozen version under
//! `outbe-zk-canonical/resources/circuits/<module>/<version>/` and records it
//! (status `active`) in `circuits/manifest.toml`. It is the only command that
//! writes frozen L1 artifacts.
//!
//! When a new version supersedes the previously-active one, the old entry is set
//! to `deprecated`, its `circuit_hash` is written into the manifest (preserving
//! its identity), and its `bytecode.b64` + `abi.json` are deleted — keeping only
//! `circuit.vk`, since verification needs only the VK (a retired prover ships its
//! own bytecode).
//!
//! `freeze-circuits --check` is the dry run CI gates on: same compile and same
//! key derivation, compared against the committed `active` artifacts, writing
//! nothing outside `target/`. It asserts the `mise.toml` toolchain pins first —
//! a key that reproduces under an unpinned `bb` proves nothing — and reports
//! every failing module before exiting 1.
//!
//! Version bump: unchanged ACIR and ABI are skipped; changed ACIR with the same ABI
//! is a patch bump; an ABI change requires `--abi-change` (minor) or `--semantic`
//! (major) so the layout/DOMAIN decision is explicit. `cargo build` never runs
//! this — it reads the frozen artifacts read-only.

use std::path::Path;
use std::process::Command;

use base64::Engine;
use toml_edit::{value, DocumentMut, Table};

use crate::noir::{self, keccak_hex};
use crate::{l2, toolchain, workspace_root};

/// Vendored noir bin circuits: (package dir under `noir/`, nargo package name).
const CIRCUITS: &[(&str, &str)] = &[
    ("outbe-emit-mint-circuit", "emit_mint"),
    ("outbe-paynote-circuit", "paynote"),
];

pub fn test_circuits() {
    let noir_dir = workspace_root()
        .join("crates")
        .join("outbe-zk-canonical")
        .join("noir");
    let nargo = toolchain::nargo();
    let packages = std::iter::once(("outbe-circuit-core", "outbe_circuit_core"))
        .chain(CIRCUITS.iter().copied())
        .map(|(dir, package)| (noir_dir.join(dir), package.to_string()))
        // Every non-revoked L2 root, too: its Noir tests are as much a gate as
        // the L1 packages'.
        .chain(l2::test_targets());

    let mut tested = 0usize;
    for (dir, package) in packages {
        println!("  testing    {package}");
        let status = Command::new(&nargo)
            .arg("test")
            .current_dir(&dir)
            .status()
            .unwrap_or_else(|e| panic!("spawn nargo for {}: {e}", dir.display()));
        if !status.success() {
            eprintln!("nargo test failed for {}", dir.display());
            std::process::exit(status.code().unwrap_or(1));
        }
        tested += 1;
    }

    println!("\n{tested} Noir package(s) tested.");
}

pub fn freeze(flags: &[String]) {
    let check = flags.iter().any(|f| f == "--check");
    let semantic = flags.iter().any(|f| f == "--semantic");
    let abi_change = flags.iter().any(|f| f == "--abi-change");

    let root = workspace_root();
    let canonical = root.join("crates").join("outbe-zk-canonical");
    let resources = canonical.join("resources/circuits");
    let manifest_path = canonical.join("circuits/manifest.toml");

    // The dry run pins the toolchain; a real freeze keeps today's looser
    // locate-only behaviour, since it is minting a new version either way.
    let (nargo, bb) = if check {
        toolchain::assert_pinned().unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        })
    } else {
        (toolchain::nargo(), toolchain::bb())
    };

    // `nargo compile` has no `--target-dir` and `noir/<pkg>/target/<module>.json`
    // is tracked, so the dry run compiles a scratch copy of the WHOLE tree —
    // whole, because each bin depends on `path = "../outbe-circuit-core"`.
    let noir_dir = canonical.join("noir");
    // Per-process, so two concurrent runs cannot delete each other's scratch
    // copy mid-compile — the same collision that flaked `l2 verify`.
    // Owned by a guard created before the copy, so a `nargo compile` panic
    // mid-check cannot leave the copied tree behind (see [`noir::Scratch`]).
    let scratch = noir::Scratch(root.join(format!("target/xtask-l1-check-{}", std::process::id())));
    let noir_dir = if check {
        let dst = scratch.0.join("noir");
        // Swept first too: a pid is reused once the process that held it is gone.
        let _ = std::fs::remove_dir_all(&scratch.0);
        noir::copy_dir(&noir_dir, &dst)
            .unwrap_or_else(|e| panic!("copy noir/ to {}: {e}", dst.display()));
        dst
    } else {
        noir_dir
    };

    let mut doc: DocumentMut = std::fs::read_to_string(&manifest_path)
        .expect("read manifest.toml")
        .parse()
        .expect("parse manifest.toml");

    let mut minted = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for (dir, module) in CIRCUITS {
        let pkg = noir_dir.join(dir);
        let compiled = noir::compile(&nargo, &pkg, module)
            .unwrap_or_else(|e| panic!("{module}: {e} (package {dir})"));
        let new_hash = keccak_hex(&compiled.acir);

        // The module's current active version, if any.
        let aot = doc["circuit"]
            .as_array_of_tables()
            .expect("[[circuit]] array");
        let active = aot.iter().enumerate().find_map(|(i, t)| {
            (t["module"].as_str() == Some(*module) && t["status"].as_str() == Some("active"))
                .then(|| (i, t["version"].as_str().unwrap().to_string()))
        });

        if check {
            match &active {
                Some((_, ver)) => failures.extend(check_version(
                    &resources.join(module).join(ver),
                    module,
                    ver,
                    &compiled,
                    &bb,
                    &scratch.0.join(".bb").join(module),
                )),
                None => failures.push(format!(
                    "{module}: no `active` entry in circuits/manifest.toml — the Noir source is not frozen"
                )),
            }
            continue;
        }

        let (new_version, supersede) = match &active {
            Some((idx, ver)) => {
                let dir_v = resources.join(module).join(ver);
                let cur_hash = frozen_hash(&dir_v).expect("active bytecode");
                let abi_differs = frozen_abi(&dir_v).as_ref() != Some(&compiled.abi);
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

        write_version(&resources, module, &new_version, &compiled, &bb);

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

    // Everything below writes. `--check` never reaches it — in particular not
    // `reconcile_artifacts`, which deletes artifacts of non-active entries.
    if check {
        // `exit` below skips destructors, so sweep before it; every other exit
        // path — success, or a panic out of `nargo`/`bb` — is the guard's.
        let _ = std::fs::remove_dir_all(&scratch.0);
        if failures.is_empty() {
            println!("\nall active L1 circuits reproduce.");
            return;
        }
        for f in &failures {
            eprintln!("{f}");
        }
        std::process::exit(1);
    }

    reconcile_artifacts(&mut doc, &resources);

    std::fs::write(&manifest_path, doc.to_string()).expect("write manifest.toml");
    println!("\n{minted} circuit(s) minted.");
}

/// Hash of a frozen version's committed ACIR: read `bytecode.b64`, decode it,
/// keccak it.
fn frozen_hash(dir_v: &Path) -> Result<String, String> {
    let b64 = std::fs::read_to_string(dir_v.join("bytecode.b64"))
        .map_err(|e| format!("bytecode.b64: {e}"))?;
    let acir = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("bytecode.b64 is not base64: {e}"))?;
    Ok(keccak_hex(&acir))
}

/// A frozen version's `abi.json`, parsed. `None` if it is missing or unreadable
/// — the callers compare structurally (key-order/format-insensitive), since a
/// raw-string compare would false-positive on serializer differences (jq vs
/// serde_json).
fn frozen_abi(dir_v: &Path) -> Option<serde_json::Value> {
    std::fs::read_to_string(dir_v.join("abi.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

/// Dry run of one `active` version: its committed ACIR, ABI and VK must all
/// reproduce from the head Noir source. Returns one message per mismatch —
/// all of them, so one CI run reports every broken circuit, not just the first.
/// `bb_scratch` is under `target/`; nothing is written under `resources/`.
fn check_version(
    dir_v: &Path,
    module: &str,
    ver: &str,
    compiled: &noir::Compiled,
    bb: &Path,
    bb_scratch: &Path,
) -> Vec<String> {
    let at = format!("{module} @ {ver}");
    let new_hash = keccak_hex(&compiled.acir);
    let mut out = Vec::new();

    match frozen_hash(dir_v) {
        Ok(cur) => {
            if cur != new_hash {
                out.push(format!(
                    "{at}: the ACIR does not reproduce — committed circuit_hash={cur}, recompiled {new_hash}"
                ));
            }
        }
        Err(e) => out.push(format!("{at}: {e}")),
    }

    if frozen_abi(dir_v).as_ref() != Some(&compiled.abi) {
        out.push(format!(
            "{at}: abi.json does not match the compiled ABI — the ABI changed and was not frozen; \
             run `cargo xtask freeze-circuits --abi-change` (minor) or `--semantic` (major)"
        ));
    }

    // The new comparison: `freeze` derives the VK and writes it, never checks
    // it, so without this the dry run would not prove the committed key
    // reproduces — which is the whole point of the job.
    let mut vk_hash = String::new();
    match noir::write_vk(bb, &compiled.json_path, bb_scratch) {
        Ok(vk) => {
            vk_hash = keccak_hex(&vk);
            match std::fs::read(dir_v.join("circuit.vk")) {
                Ok(cur) if cur == vk => {}
                Ok(cur) => out.push(format!(
                    "{at}: circuit.vk does not reproduce — committed {} ({} bytes), recomputed {vk_hash} ({} bytes)",
                    keccak_hex(&cur),
                    cur.len(),
                    vk.len(),
                )),
                Err(e) => out.push(format!("{at}: circuit.vk: {e}")),
            }
        }
        Err(e) => out.push(format!("{at}: {e}")),
    }

    if out.is_empty() {
        println!("  reproduces {at}  circuit_hash={new_hash} vk_hash={vk_hash}");
    }
    out
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
            if let Ok(hash) = frozen_hash(&dir) {
                doc["circuit"]
                    .as_array_of_tables_mut()
                    .unwrap()
                    .get_mut(i)
                    .unwrap()["circuit_hash"] = value(hash);
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
    compiled: &noir::Compiled,
    bb: &Path,
) {
    let dir = resources.join(module).join(version);
    std::fs::create_dir_all(&dir).expect("mkdir version dir");
    std::fs::write(dir.join("bytecode.b64"), &compiled.bytecode_b64).expect("write bytecode.b64");
    let abi_str = serde_json::to_string(&compiled.abi).expect("serialize abi");
    std::fs::write(dir.join("abi.json"), abi_str).expect("write abi.json");

    let vk = noir::write_vk(bb, &compiled.json_path, &dir.join(".bb"))
        .unwrap_or_else(|e| panic!("{module}: {e}"));
    std::fs::write(dir.join("circuit.vk"), vk).expect("install circuit.vk");
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
        "emit_mint" => "outbe.emit.mint".to_string(),
        "paynote" => "outbe.paynote".to_string(),
        m => panic!("unknown module {m}"),
    }
}
