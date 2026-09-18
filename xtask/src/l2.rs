//! L2 registry commands. Writes only under `crates/outbe-l2-zk-canonical/`
//! and `target/xtask-l2/`. It reads two files outside that crate:
//! `crates/outbe-zk-canonical/circuits/manifest.toml`, whose `proof_system`
//! [`assert_toolchain`] compares the L2 one against, and `mise.toml`, read for
//! the `nargo`/`bb` pins by the [`toolchain::assert_pinned`] it calls. Both
//! are in [`TOOLCHAIN_FILES`], the set a `--changed` run widens on.
//!
//! `l2 verify` proves a committed key came from its committed source: it
//! recompiles the root with the pinned toolchain in a scratch copy and compares
//! the ABI, the key and the circuit hash byte for byte. It writes nothing
//! outside `target/`.
//!
//! Order matters. Entry selection runs off committed files, then the toolchain
//! assertion once for the whole run; per root, hygiene and the committed-ABI-
//! against-claim-ABI comparison both run before the compile. A `nargo compile`
//! or `bb write_vk` failure can then never stand in for a defect those reads
//! would have named.
//!
//! `l2 admit` runs the same compile and derive, then writes `abi.json`,
//! `circuit.vk` and `circuit.hash` into the root and appends one
//! `[[l2_circuit]]` entry. An L2 team can skip it and commit the three files by
//! hand; `verify` proves them either way.

use std::path::{Path, PathBuf};
use std::process::Command;

use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

use crate::noir::{self, keccak_hex};
use crate::{toolchain, workspace_root};

const CRATE: &str = "crates/outbe-l2-zk-canonical";

/// Workspace files that can stop *any* committed key reproducing, so a change
/// to one widens `--changed` to every live entry: the `nargo`/`bb` pins
/// (`mise.toml`), the `barretenberg-rs` pin (the workspace manifest) and
/// `proof_system` (the L1 manifest, which `assert_toolchain` compares the L2
/// one against).
const TOOLCHAIN_FILES: &[&str] = &[
    "mise.toml",
    "Cargo.toml",
    "crates/outbe-zk-canonical/circuits/manifest.toml",
];

/// One `[[l2_circuit]]`. `root` is crate-relative with `/` separators.
pub struct Entry {
    chain_id: u64,
    claim: String,
    version: String,
    status: String,
    root: String,
}

impl Entry {
    fn slug(&self) -> String {
        format!("{}/{}/{}", self.chain_id, self.claim, self.version)
    }
    fn dir(&self) -> PathBuf {
        crate_dir().join(&self.root)
    }
}

fn crate_dir() -> PathBuf {
    workspace_root().join(CRATE)
}

fn manifest_path() -> PathBuf {
    crate_dir().join("l2/manifest.toml")
}

fn load_manifest() -> Result<DocumentMut, String> {
    std::fs::read_to_string(manifest_path())
        .map_err(|e| format!("l2/manifest.toml: {e}"))?
        .parse()
        .map_err(|e| format!("l2/manifest.toml: parse error: {e}"))
}

fn entries(doc: &DocumentMut) -> Result<Vec<Entry>, String> {
    let Some(aot) = doc.get("l2_circuit").and_then(Item::as_array_of_tables) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(aot.len());
    for (i, t) in aot.iter().enumerate() {
        let str_key = |k: &str| {
            t.get(k)
                .and_then(Item::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("l2/manifest.toml: [[l2_circuit]] #{i} has no `{k}`"))
        };
        let chain_id = t
            .get("chain_id")
            .and_then(Item::as_integer)
            .and_then(|v| u64::try_from(v).ok())
            .ok_or_else(|| format!("l2/manifest.toml: [[l2_circuit]] #{i} has no `chain_id`"))?;
        out.push(Entry {
            chain_id,
            claim: str_key("claim")?,
            version: str_key("version")?,
            status: str_key("status")?,
            root: str_key("root")?,
        });
    }
    // `(chain_id, claim, version)` is unique — build.rs enforces it too, but a
    // duplicate makes every selection ambiguous, so catch it here first.
    for (i, a) in out.iter().enumerate() {
        for b in &out[i + 1..] {
            if (a.chain_id, &a.claim, &a.version) == (b.chain_id, &b.claim, &b.version) {
                return Err(format!(
                    "l2/manifest.toml: duplicate entry {} — (chain_id, claim, version) must be unique",
                    a.slug()
                ));
            }
        }
    }
    Ok(out)
}

/// `(root dir, label)` for every non-revoked root, for `test-circuits`.
/// Silent on a missing or malformed manifest: hygiene is `verify`'s job.
pub fn test_targets() -> Vec<(PathBuf, String)> {
    load_manifest()
        .and_then(|doc| entries(&doc))
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.status != "revoked")
        .map(|e| (e.dir(), e.slug()))
        .collect()
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

pub fn verify(args: &[String]) {
    if let Err(e) = run_verify(args) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run_verify(args: &[String]) -> Result<(), String> {
    let doc = load_manifest()?;
    let all = entries(&doc)?;
    let selected = select(args, &all)?;
    if selected.is_empty() {
        println!("no L2 roots to verify.");
        return Ok(());
    }

    let (nargo, bb) = assert_toolchain(&doc)?;

    for e in &selected {
        println!("  re-deriving the key from src/  {}", e.slug());
        verify_entry(e, &nargo, &bb).map_err(|m| format!("{}: {m}", e.slug()))?;
    }
    // The whole point of the command, said once: a merged root is pinned to its
    // key, and this is the proof that the committed key is still the key that
    // source compiles to.
    println!(
        "\n{} L2 root(s) verified: every committed circuit.vk re-derived from its own src/ and byte-identical.",
        selected.len()
    );
    Ok(())
}

fn verify_entry(e: &Entry, nargo: &Path, bb: &Path) -> Result<(), String> {
    let root = e.dir();

    // 2-3. Everything that needs no toolchain runs first, so a `nargo`/`bb`
    //      failure can never mask a defect a plain file read would have found.
    let pkg = check_hygiene(&root, &e.root)?;
    let committed_abi: serde_json::Value = serde_json::from_str(&read_artifact(&root, "abi.json")?)
        .map_err(|err| format!("abi.json is not valid JSON: {err}"))?;
    check_claim_abi(&committed_abi, &e.claim)?;
    let vk_committed = std::fs::read(root.join("circuit.vk"))
        .map_err(|_| "circuit.vk missing from root".to_string())?;
    let committed_hash = read_artifact(&root, "circuit.hash")?;

    // 4. Only now the expensive half.
    let built = build(nargo, bb, &root, &pkg, &e.slug())?;

    // 5. Committed abi.json == the compiled ABI. Structural, not a raw-string
    //    compare: that would false-positive on serializer differences, exactly
    //    as the L1 freeze path documents. The claim ABI follows by transitivity,
    //    since the committed ABI was checked against it above.
    if committed_abi != built.abi {
        // Beside the scratch copy, not inside it: the copy is swept on the way out.
        let dump = built
            .scratch
            .0
            .with_file_name(format!("{}.abi.compiled.json", e.slug().replace('/', "-")));
        let _ = std::fs::write(
            &dump,
            serde_json::to_string_pretty(&built.abi).unwrap_or_default(),
        );
        return Err(format!(
            "abi.json does not match the compiled ABI — compiled ABI written to {}, diff it against {}/abi.json",
            dump.display(),
            e.root
        ));
    }

    // 6. circuit.vk reproduces byte for byte.
    if vk_committed != built.vk {
        return Err(format!(
            "circuit.vk does not reproduce from src/ — committed {} ({} bytes), recompiled {} ({} bytes)",
            keccak_hex(&vk_committed),
            vk_committed.len(),
            keccak_hex(&built.vk),
            built.vk.len(),
        ));
    }

    // 7. circuit.hash == keccak256(acir).
    let circuit_hash = keccak_hex(&built.acir);
    if committed_hash.trim() != circuit_hash {
        return Err(format!(
            "circuit.hash {} != keccak256(acir) {circuit_hash}",
            committed_hash.trim()
        ));
    }

    println!(
        "  verified   {}  key still matches src/  circuit_hash={circuit_hash} vk_hash={}",
        e.slug(),
        keccak_hex(&built.vk)
    );
    Ok(())
}

/// Read one committed root artifact, naming it rather than the io error.
fn read_artifact(root: &Path, name: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(name)).map_err(|_| format!("{name} missing from root"))
}

// ---------------------------------------------------------------------------
// admit
// ---------------------------------------------------------------------------

pub fn admit(args: &[String]) {
    if let Err(e) = run_admit(args) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run_admit(args: &[String]) -> Result<(), String> {
    let path = flag_value(args, "--root")
        .ok_or("l2 admit: --root PATH is required")?
        .clone();
    let root_rel = crate_relative(&path)?;
    let root = crate_dir().join(&root_rel);

    // The path IS the key: no --chain/--claim/--version flags to disagree with it.
    let parts: Vec<&str> = root_rel.split('/').collect();
    let bad = || format!("admit: root must be l2/<chain_id>/<claim>/<version>, got \"{root_rel}\"");
    let [l2, chain, claim, version] = parts[..] else {
        return Err(bad());
    };
    if l2 != "l2" || version.split('.').count() != 3 {
        return Err(bad());
    }
    let chain_id: u64 = chain.parse().map_err(|_| bad())?;

    let mut doc = load_manifest()?;
    for e in entries(&doc)? {
        if (e.chain_id, e.claim.as_str(), e.version.as_str()) == (chain_id, claim, version) {
            return Err(format!(
                "admit: l2/manifest.toml already has chain_id = {chain_id}, claim = \"{claim}\", version = \"{version}\""
            ));
        }
        if e.root == root_rel {
            return Err(format!(
                "admit: l2/manifest.toml already has root = \"{root_rel}\""
            ));
        }
    }
    for artifact in ["abi.json", "circuit.vk", "circuit.hash"] {
        if root.join(artifact).exists() {
            return Err(format!(
                "admit: {root_rel}/{artifact} exists; a merged root is immutable — bump the version or delete the artifacts deliberately"
            ));
        }
    }

    let slug = format!("{chain_id}/{claim}/{version}");
    let pkg = check_hygiene(&root, &root_rel).map_err(|m| format!("{slug}: {m}"))?;
    let (nargo, bb) = assert_toolchain(&doc)?;
    let built = build(&nargo, &bb, &root, &pkg, &slug).map_err(|m| format!("{slug}: {m}"))?;
    check_claim_abi(&built.abi, claim).map_err(|m| format!("{slug}: {m}"))?;

    let circuit_hash = keccak_hex(&built.acir);
    write(
        &root.join("abi.json"),
        serde_json::to_string(&built.abi)
            .expect("serialize abi")
            .as_bytes(),
    )?;
    write(&root.join("circuit.vk"), &built.vk)?;
    write(
        &root.join("circuit.hash"),
        format!("{circuit_hash}\n").as_bytes(),
    )?;

    let mut t = Table::new();
    t["chain_id"] = value(i64::try_from(chain_id).map_err(|_| bad())?);
    t["claim"] = value(claim);
    t["version"] = value(version);
    t["status"] = value("active");
    t["root"] = value(&root_rel);
    t.decor_mut().set_prefix("\n");
    if doc.get("l2_circuit").is_none() {
        doc["l2_circuit"] = Item::ArrayOfTables(ArrayOfTables::new());
    }
    doc["l2_circuit"]
        .as_array_of_tables_mut()
        .ok_or("l2/manifest.toml: `l2_circuit` is not an array of tables")?
        .push(t);
    write(&manifest_path(), doc.to_string().as_bytes())?;

    println!(
        "  admitted   {slug}  circuit_hash={circuit_hash} vk_hash={}",
        keccak_hex(&built.vk)
    );
    println!("run: cargo xtask l2 verify --root {CRATE}/{root_rel}");
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// selection
// ---------------------------------------------------------------------------

fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
}

fn select<'a>(args: &[String], all: &'a [Entry]) -> Result<Vec<&'a Entry>, String> {
    let has = |f: &str| args.iter().any(|a| a == f);
    let root = flag_value(args, "--root");
    if usize::from(root.is_some()) + usize::from(has("--changed")) + usize::from(has("--all")) != 1
    {
        return Err("l2 verify: pass exactly one of --root PATH, --changed, --all".to_string());
    }

    // A `revoked` entry whose root survived is a failure in every mode:
    // revocation deletes the root in the same pull request.
    for e in all.iter().filter(|e| e.status == "revoked") {
        if e.dir().exists() {
            return Err(format!(
                "{}: entry is revoked but {} still exists; revocation deletes the root in the same pull request",
                e.slug(),
                e.root
            ));
        }
    }

    if let Some(path) = root {
        let rel = crate_relative(path)?;
        let e = all.iter().find(|e| e.root == rel).ok_or_else(|| {
            format!("no [[l2_circuit]] entry with root = \"{rel}\" in l2/manifest.toml")
        })?;
        // The root of a revoked entry is gone by rule, so say why rather than
        // report the deleted directory as a missing one.
        if e.status == "revoked" {
            return Err(format!(
                "{}: entry is revoked — its key is dropped from the generated table and its root is deleted, so there is nothing to reproduce",
                e.slug()
            ));
        }
        return Ok(vec![e]);
    }

    let live = || all.iter().filter(|e| e.status != "revoked");

    if has("--all") {
        return Ok(live().collect());
    }

    // --changed: roots touched against the base branch. A claim ABI or a
    // toolchain bump widens the set, since either can stop a key reproducing.
    // The L2 manifest's own `proof_system` needs no entry in TOOLCHAIN_FILES:
    // `assert_toolchain` requires it to equal the L1 one, so a real change
    // touches both files and the L1 one is listed.
    let changed = changed_paths(flag_value(args, "--base").map(String::as_str))?;
    if changed
        .iter()
        .any(|p| TOOLCHAIN_FILES.contains(&p.as_str()))
    {
        return Ok(live().collect());
    }
    let manifest_roots = changed
        .iter()
        .any(|p| p == &format!("{CRATE}/l2/manifest.toml"))
        .then(|| added_roots(flag_value(args, "--base").map(String::as_str)))
        .transpose()?
        .unwrap_or_default();

    Ok(live()
        .filter(|e| {
            let root_prefix = format!("{CRATE}/{}/", e.root);
            let claim_abi = format!("{CRATE}/claims/{}/abi.json", e.claim);
            manifest_roots.contains(&e.root)
                || changed
                    .iter()
                    .any(|p| p.starts_with(&root_prefix) || p == &claim_abi)
        })
        .collect())
}

fn git(args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(workspace_root())
        .output()
        .map_err(|e| format!("--changed: spawn git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "--changed: `git {}` failed; use --root or --all",
            args.join(" ")
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn merge_base(base: Option<&str>) -> Result<String, String> {
    let base = base.map(str::to_string).unwrap_or_else(|| {
        std::env::var("GITHUB_BASE_REF")
            .map(|b| format!("origin/{b}"))
            .unwrap_or_else(|_| "origin/main".to_string())
    });
    git(&["merge-base", &base, "HEAD"])
}

/// Repo-relative paths that differ from the merge base. Index, worktree and
/// untracked files are included, so a local `--changed` on a root that is not
/// committed yet still selects it.
fn changed_paths(base: Option<&str>) -> Result<Vec<String>, String> {
    let sha = merge_base(base)?;
    let tracked = git(&["diff", "--name-only", &sha])?;
    let untracked = git(&["ls-files", "--others", "--exclude-standard"])?;
    Ok(tracked
        .lines()
        .chain(untracked.lines())
        .map(str::to_string)
        .collect())
}

/// Roots named by `root = "..."` lines the manifest diff ADDS. A status flip or
/// a comment adds no root line and so selects nothing extra.
fn added_roots(base: Option<&str>) -> Result<Vec<String>, String> {
    let sha = merge_base(base)?;
    let manifest = format!("{CRATE}/l2/manifest.toml");
    let diff = git(&["diff", "--unified=0", &sha, "--", &manifest])?;
    Ok(diff
        .lines()
        .filter(|l| l.starts_with('+'))
        .filter_map(|l| {
            l.split_once("root")?
                .1
                .split('"')
                .nth(1)
                .map(str::to_string)
        })
        .collect())
}

/// Normalise a user-supplied path to a crate-relative `/`-separated root.
///
/// The path need not exist: a revoked entry's root is deleted by rule, and
/// `--root` on one must reach the manifest lookup to report the revocation
/// rather than stop at a missing directory. So the deepest existing ancestor
/// is canonicalised and the missing tail re-appended.
fn crate_relative(path: &str) -> Result<String, String> {
    let base = std::fs::canonicalize(crate_dir())
        .map_err(|e| format!("{}: {e}", crate_dir().display()))?;

    let full = PathBuf::from(path);
    let mut head: &Path = &full;
    let mut tail = Vec::new();
    let abs = loop {
        if let Ok(c) = std::fs::canonicalize(head) {
            break tail.iter().rev().fold(c, |acc, n| acc.join(n));
        }
        let name = head
            .file_name()
            .ok_or_else(|| format!("--root {path}: no such path"))?;
        tail.push(name.to_owned());
        head = head
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| format!("--root {path}: no such path"))?;
    };

    abs.strip_prefix(&base)
        .map_err(|_| format!("--root {path} is not inside {CRATE}"))
        .map(|r| r.to_string_lossy().replace('\\', "/"))
}

// ---------------------------------------------------------------------------
// checks
// ---------------------------------------------------------------------------

/// Tool versions equal the `mise.toml` pins and the L2 `proof_system` equals
/// the L1 one. Runs once, before any compile.
fn assert_toolchain(doc: &DocumentMut) -> Result<(PathBuf, PathBuf), String> {
    let ours = doc
        .get("proof_system")
        .and_then(Item::as_str)
        .ok_or("l2/manifest.toml: proof_system missing")?;
    let l1_path = workspace_root().join("crates/outbe-zk-canonical/circuits/manifest.toml");
    let l1: DocumentMut = std::fs::read_to_string(&l1_path)
        .map_err(|e| format!("{}: {e}", l1_path.display()))?
        .parse()
        .map_err(|e| format!("{}: parse error: {e}", l1_path.display()))?;
    let theirs = l1
        .get("proof_system")
        .and_then(Item::as_str)
        .ok_or("outbe-zk-canonical circuits/manifest.toml: proof_system missing")?;
    if ours != theirs {
        return Err(format!(
            "l2/manifest.toml: proof_system {ours:?} != outbe-zk-canonical circuits/manifest.toml proof_system {theirs:?}"
        ));
    }
    toolchain::assert_pinned()
}

/// Root hygiene. Returns the nargo package name, which names the artifact.
fn check_hygiene(root: &Path, root_rel: &str) -> Result<String, String> {
    if !root.is_dir() {
        return Err(format!("root directory {root_rel} missing"));
    }
    let nargo_toml = root.join("Nargo.toml");
    let doc: DocumentMut = std::fs::read_to_string(&nargo_toml)
        .map_err(|_| "Nargo.toml missing from root".to_string())?
        .parse()
        .map_err(|e| format!("Nargo.toml: {e}"))?;

    match doc["package"].get("type").and_then(Item::as_str) {
        Some("bin") => {}
        Some(other) => {
            return Err(format!(
                "Nargo.toml: package type is {other:?}, must be \"bin\""
            ))
        }
        None => return Err("Nargo.toml: [package] type missing, must be \"bin\"".to_string()),
    }
    let package = doc["package"]
        .get("name")
        .and_then(Item::as_str)
        .ok_or("Nargo.toml: [package] name missing")?
        .to_string();
    if !root.join("src/main.nr").is_file() {
        return Err("src/main.nr missing".to_string());
    }

    let canonical_root =
        std::fs::canonicalize(root).map_err(|e| format!("canonicalize root: {e}"))?;
    if let Some(deps) = doc.get("dependencies").and_then(Item::as_table_like) {
        for (name, item) in deps.iter() {
            let Some(dep) = item.as_table_like() else {
                continue;
            };
            if let Some(p) = dep.get("path").and_then(Item::as_str) {
                let target = std::fs::canonicalize(root.join(p))
                    .map_err(|_| format!("dependency {name:?} path {p:?} does not exist"))?;
                if !target.starts_with(&canonical_root) {
                    return Err(format!(
                        "dependency {name:?} has path {p:?} escaping the root; L2 roots are self-contained"
                    ));
                }
            }
            if dep.get("git").is_some() && dep.get("tag").is_none() && dep.get("rev").is_none() {
                return Err(format!(
                    "dependency {name:?} is a git dependency without a tag or rev; pin it"
                ));
            }
        }
    }
    Ok(package)
}

struct Built {
    acir: Vec<u8>,
    abi: serde_json::Value,
    vk: Vec<u8>,
    /// Removed when this `Built` drops, on every exit path.
    scratch: noir::Scratch,
}

/// Compile the root in a scratch copy (`nargo compile` has no `--target-dir`,
/// and a committed root must not gain an untracked `target/`), then derive the
/// key from the compiled artifact.
fn build(nargo: &Path, bb: &Path, root: &Path, package: &str, slug: &str) -> Result<Built, String> {
    // One scratch directory per process. A shared, slug-only path is the cause
    // of the "bb write_vk failed in the scratch directory" flake: two xtask
    // runs over the same root (a local `--all` beside a `--root`, CI's
    // `l2-verify` beside the demo's `reproduce` test) share it, and the second
    // one's `remove_dir_all` deletes the first one's sources mid-run, which
    // surfaces as an unrelated `nargo compile` or `bb write_vk` failure.
    let scratch = noir::Scratch(workspace_root().join("target/xtask-l2").join(format!(
        "{}-{}",
        slug.replace('/', "-"),
        std::process::id()
    )));
    // Still swept first: a pid is reused once the process that held it is gone.
    let _ = std::fs::remove_dir_all(&scratch.0);
    noir::copy_dir(root, &scratch.0)
        .map_err(|e| format!("copy root to {}: {e}", scratch.0.display()))?;

    let compiled = noir::compile(nargo, &scratch.0, package)?;
    let vk = noir::write_vk(bb, &compiled.json_path, &scratch.0.join(".bb"))?;
    Ok(Built {
        acir: compiled.acir,
        abi: compiled.abi,
        vk,
        scratch,
    })
}

/// The root's public parameters equal `claims/<claim>/abi.json` in name, type
/// and order. A different layout is a different claim.
fn check_claim_abi(abi: &serde_json::Value, claim: &str) -> Result<(), String> {
    let path = crate_dir().join(format!("claims/{claim}/abi.json"));
    let text = std::fs::read_to_string(&path).map_err(|_| {
        format!("claims/{claim}/abi.json not found; the manifest entry names claim {claim:?}")
    })?;
    let claim_abi: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("claims/{claim}/abi.json is not valid JSON: {e}"))?;

    let want = claim_abi["parameters"]
        .as_array()
        .ok_or_else(|| format!("claims/{claim}/abi.json has no `parameters` array"))?;
    let got: Vec<&serde_json::Value> = abi["parameters"]
        .as_array()
        .ok_or("the compiled ABI has no `parameters` array")?
        .iter()
        .filter(|p| p["visibility"] == "public")
        .collect();

    if got.len() != want.len() {
        return Err(format!(
            "root exposes {} public parameters, claim {claim:?} declares {}",
            got.len(),
            want.len()
        ));
    }
    for (i, (g, w)) in got.iter().zip(want).enumerate() {
        if g["name"] != w["name"] {
            return Err(format!(
                "public parameter {i} is named {}, claim {claim:?} declares {}",
                g["name"], w["name"]
            ));
        }
        if g["type"] != w["type"] {
            return Err(format!(
                "public parameter {i} {} has type {}, claim {claim:?} declares {}",
                g["name"], g["type"], w["type"]
            ));
        }
    }
    Ok(())
}
