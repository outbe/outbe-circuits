//! `cargo xtask` — canonical-circuit tooling.
//!
//! `test-circuits` runs every vendored Noir package through `nargo test`.
//!
//! `freeze-circuits` compiles catalog packages. L1 circuits mint immutable
//! releases under `resources/circuits/<module>/<version>`; L2 packages refresh
//! flat artifacts in place, subject to every registered stable VK pin.
//! Chain versions are always declared explicitly, never automatically bumped.
//! `--check` reproduces L1 artifacts and L2 pinned keys in a scratch tree under
//! `target/`, without modifying committed files.
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

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use tiny_keccak::{Hasher, Keccak};
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

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
    let canonical = workspace_root().join("crates/outbe-zk-canonical");
    let doc: DocumentMut = std::fs::read_to_string(canonical.join("circuits/manifest.toml"))
        .expect("read manifest.toml")
        .parse()
        .expect("parse manifest.toml");
    let nargo = locate("NARGO", ".nargo/bin/nargo", "nargo").expect("nargo not found (set $NARGO)");

    let mut tested = 0usize;
    let catalog = catalog(&doc, &canonical).expect("valid circuit catalog");
    for source in &catalog.sources {
        let pkg = canonical.join(source);
        let package = package_name(&pkg).expect("read Nargo package name");
        println!("  testing    {package}");
        let status = Command::new(&nargo)
            .arg("test")
            .current_dir(&pkg)
            .status()
            .unwrap_or_else(|e| panic!("spawn nargo for {}: {e}", source.display()));
        if !status.success() {
            eprintln!("nargo test failed for {}", source.display());
            std::process::exit(status.code().unwrap_or(1));
        }
        tested += 1;
    }

    println!("\n{tested} Noir package(s) tested.");
}

struct Catalog {
    sources: Vec<PathBuf>,
    l1_sources: HashMap<String, PathBuf>,
    l2: Vec<L2Package>,
}

struct L2Package {
    source: PathBuf,
    references: Vec<L2Reference>,
}

struct L2Reference {
    chain: usize,
    version: usize,
    circuit: usize,
    stable: bool,
    pin: Option<String>,
}

fn relative_path(path: &str) -> Result<&Path, Box<dyn Error>> {
    let invalid = path.contains(['\\', ':'])
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..");
    let path = Path::new(path);
    if invalid
        || path
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(format!("expected a non-escaping relative path: {}", path.display()).into());
    }
    Ok(path)
}

fn package_path(root: &Path, path: &str) -> Result<PathBuf, Box<dyn Error>> {
    let resolved = root.join(relative_path(path)?).canonicalize()?;
    let root = root.canonicalize()?;
    Ok(resolved
        .strip_prefix(&root)
        .map_err(|_| format!("package escapes {}: {path}", root.display()))?
        .to_owned())
}

fn catalog(doc: &DocumentMut, canonical: &Path) -> Result<Catalog, Box<dyn Error>> {
    let mut catalog = Catalog {
        sources: Vec::new(),
        l1_sources: HashMap::new(),
        l2: Vec::new(),
    };
    let mut modules = HashSet::new();
    if let Some(libraries) = doc.get("libraries").and_then(Item::as_array) {
        for library in libraries {
            catalog.sources.push(package_path(
                canonical,
                library.as_str().ok_or("library must be a path")?,
            )?);
        }
    }
    if let Some(circuits) = doc.get("circuit").and_then(Item::as_array_of_tables) {
        for circuit in circuits {
            let module = circuit["module"].as_str().ok_or("missing circuit module")?;
            if relative_path(module)?.components().count() != 1
                || !modules.insert(module.to_owned())
            {
                return Err(format!("invalid or duplicate circuit module: {module}").into());
            }
            let mut releases = HashSet::new();
            let mut active = 0;
            let mut all_revoked = false;
            if let Some(versions) = circuit.get("versions").and_then(Item::as_array_of_tables) {
                all_revoked = !versions.is_empty();
                for version in versions {
                    let name = version["version"]
                        .as_str()
                        .ok_or("missing circuit version")?;
                    if relative_path(name)?.components().count() != 1 || !releases.insert(name) {
                        return Err(format!("{module}: invalid or duplicate version {name}").into());
                    }
                    let status = version["status"].as_str().ok_or("missing circuit status")?;
                    if !matches!(status, "active" | "deprecated" | "revoked") {
                        return Err(format!("{module}: unknown status {status}").into());
                    }
                    active += usize::from(status == "active");
                    all_revoked &= status == "revoked";
                }
            }
            if active > 1 {
                return Err(format!("{module}: multiple active releases").into());
            }
            if !all_revoked {
                let source = package_path(canonical, &format!("noir/{module}"))?;
                catalog.sources.push(source.clone());
                catalog.l1_sources.insert(module.to_owned(), source);
            }
        }
    }
    let mut chains = HashSet::new();
    if let Some(entries) = doc.get("l2_chain").and_then(Item::as_array_of_tables) {
        for (chain_index, chain) in entries.iter().enumerate() {
            let chain_id = chain["chain_id"].as_integer().ok_or("missing chain_id")?;
            if chain_id < 0 || !chains.insert(chain_id) {
                return Err(format!("invalid or duplicate chain_id: {chain_id}").into());
            }
            let chain_root = canonical.join(format!("l2/{chain_id}"));
            let mut versions = HashSet::new();
            for (version_index, version) in chain["versions"]
                .as_array_of_tables()
                .ok_or("missing chain versions")?
                .iter()
                .enumerate()
            {
                let name = version["version"].as_str().ok_or("missing chain version")?;
                if name.trim().is_empty() || !versions.insert(name) {
                    return Err(
                        format!("chain {chain_id}: empty or duplicate version {name:?}").into(),
                    );
                }
                let stable = version["stable"].as_bool().ok_or("missing stable flag")?;
                let mut paths = HashSet::new();
                for (circuit_index, entry) in version["circuits"]
                    .as_array()
                    .ok_or("missing chain circuits")?
                    .iter()
                    .enumerate()
                {
                    let entry = entry
                        .as_inline_table()
                        .ok_or("circuit must be an inline table")?;
                    let path = entry
                        .get("path")
                        .and_then(|v| v.as_str())
                        .ok_or("missing circuit path")?;
                    // Resolve aliases before deduplication; confinement is both lexical and physical.
                    package_path(&chain_root, path)?;
                    let source = package_path(canonical, &format!("l2/{chain_id}/{path}"))?;
                    if !paths.insert(source.clone()) {
                        return Err(
                            format!("chain {chain_id} @ {name}: duplicate package {path}").into(),
                        );
                    }
                    let pin = entry
                        .get("vk_hash")
                        .map(|v| {
                            let pin = v.as_str().ok_or("vk_hash must be a string")?;
                            if pin.len() != 64
                                || !pin
                                    .bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                            {
                                return Err("vk_hash must contain 64 lowercase hex digits");
                            }
                            Ok(pin.to_owned())
                        })
                        .transpose()?;
                    let index = catalog
                        .l2
                        .iter()
                        .position(|package| package.source == source);
                    let package = match index {
                        Some(index) => &mut catalog.l2[index],
                        None => {
                            catalog.sources.push(source.clone());
                            catalog.l2.push(L2Package {
                                source,
                                references: Vec::new(),
                            });
                            catalog.l2.last_mut().unwrap()
                        }
                    };
                    if pin.as_ref().is_some_and(|pin| {
                        package.references.iter().any(|reference| {
                            reference.pin.as_ref().is_some_and(|other| other != pin)
                        })
                    }) {
                        return Err(format!(
                            "{}: conflicting shared VK pins",
                            package.source.display()
                        )
                        .into());
                    }
                    package.references.push(L2Reference {
                        chain: chain_index,
                        version: version_index,
                        circuit: circuit_index,
                        stable,
                        pin,
                    });
                }
            }
        }
    }
    let mut seen = HashSet::new();
    catalog.sources.retain(|source| seen.insert(source.clone()));
    let mut names = HashMap::new();
    for source in &catalog.sources {
        let name = package_name(&canonical.join(source))?;
        if catalog.l2.iter().any(|package| &package.source == source) && modules.contains(&name) {
            return Err(format!(
                "L2 package {} conflicts with L1 module {name}",
                source.display()
            )
            .into());
        }
        if let Some(other) = names.insert(name.clone(), source) {
            return Err(format!(
                "duplicate Nargo package name {name}: {} and {}",
                other.display(),
                source.display()
            )
            .into());
        }
    }
    Ok(catalog)
}

fn package_name(package: &Path) -> Result<String, Box<dyn Error>> {
    let path = package.join("Nargo.toml");
    let doc: DocumentMut = std::fs::read_to_string(&path)?.parse()?;
    let name = doc
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(Item::as_str)
        .ok_or_else(|| format!("{}: missing package.name", path.display()))?;
    Ok(name.to_owned())
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
    let manifest_path = canonical.join("circuits/manifest.toml");
    let mut doc: DocumentMut = std::fs::read_to_string(&manifest_path)?.parse()?;
    let catalog = catalog(&doc, &canonical)?;

    let nargo = locate("NARGO", ".nargo/bin/nargo", "nargo").expect("nargo not found (set $NARGO)");
    let bb = locate("BB", ".bb/bb", "bb").expect("bb not found (set $BB)");
    if check {
        assert_pinned(&root, &nargo, &bb)?;
    }

    // Preserve crate-relative package locations so path dependencies resolve.
    // The guard is live before copying or compiling, including on failures.
    let scratch = Scratch::new(&root.join("target"))?;
    let source_root = if check {
        for source in &catalog.sources {
            copy_noir(&canonical.join(source), &scratch.0.join(source))?;
        }
        &scratch.0
    } else {
        &canonical
    };

    let mut minted = 0usize;
    let mut failures = Vec::new();
    for circuit in doc
        .get_mut("circuit")
        .and_then(Item::as_array_of_tables_mut)
        .into_iter()
        .flat_map(|circuits| circuits.iter_mut())
    {
        let module = circuit["module"].as_str().expect("circuit module");
        let Some(source) = catalog.l1_sources.get(module) else {
            continue;
        };
        let artifacts = canonical.join("resources/circuits").join(module);
        let (json_path, json) = compile(&nargo, &source_root.join(source))?;
        let bytecode = json["bytecode"].as_str().expect("bytecode");
        let abi_str = serde_json::to_string(&json["abi"]).expect("serialize abi");
        let acir = base64::engine::general_purpose::STANDARD
            .decode(bytecode)
            .expect("base64");
        let new_hash = keccak_hex(&acir);

        let active = circuit
            .get("versions")
            .and_then(Item::as_array_of_tables)
            .and_then(|versions| {
                versions.iter().enumerate().find_map(|(i, version)| {
                    (version["status"].as_str() == Some("active"))
                        .then(|| (i, version["version"].as_str().expect("version")))
                })
            });

        if check {
            match active {
                Some((_, ver)) => {
                    // Always derive the VK, even when ACIR and ABI match.
                    let result = write_vk(&bb, &json_path, &scratch.0.join(".bb").join(module))
                        .and_then(|path| {
                            check_version(
                                &artifacts.join(ver),
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

        let (new_version, supersede) = match active {
            Some((idx, ver)) => {
                let dir_v = artifacts.join(ver);
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
                (nv, Some((idx, cur_hash)))
            }
            None => ("1.0.0".to_string(), None),
        };

        if circuit
            .get("versions")
            .and_then(Item::as_array_of_tables)
            .is_some_and(|versions| {
                versions
                    .iter()
                    .any(|version| version["version"].as_str() == Some(new_version.as_str()))
            })
        {
            return Err(format!("{module}: frozen version {new_version} already exists").into());
        }
        write_version(
            &artifacts.join(&new_version),
            bytecode,
            &abi_str,
            &bb,
            &json_path,
        );

        match active {
            Some((_, ver)) => {
                println!("  minted     {module} {ver} -> {new_version}  (old -> deprecated)");
            }
            None => println!("  minted     {module} @ {new_version}  (new)"),
        }
        record_version(circuit, &new_version, supersede);
        minted += 1;
    }
    // Derive and validate every package before refreshing any L2 artifacts.
    // In particular, visiting a mutable registration first cannot bypass a
    // stable registration of that same physical package.
    let mut compiled = Vec::new();
    for (index, package) in catalog.l2.iter().enumerate() {
        let (json_path, json) = compile(&nargo, &source_root.join(&package.source))?;
        let key_path = write_vk(
            &bb,
            &json_path,
            &scratch.0.join(".bb/l2").join(index.to_string()),
        )?;
        let vk = std::fs::read(key_path)?;
        let hash = keccak_hex(&vk);
        validate_l2_key(
            &canonical.join(&package.source),
            &package.references,
            &hash,
            check,
        )
        .map_err(|error| format!("{}: {error}", package.source.display()))?;
        compiled.push((package, json, vk, hash));
    }
    for (package, json, vk, hash) in compiled {
        if check {
            println!("  reproduces {}", package.source.display());
        } else {
            refresh_l2(&canonical.join(&package.source), &json, &vk)?;
            update_l2_pins(&mut doc, &package.references, &hash);
            println!("  refreshed  {}", package.source.display());
        }
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

    reconcile_artifacts(&mut doc, &canonical);

    std::fs::write(&manifest_path, doc.to_string()).expect("write manifest.toml");
    println!("\n{minted} circuit(s) minted.");
    Ok(())
}

fn compile(nargo: &Path, package: &Path) -> Result<(PathBuf, serde_json::Value), Box<dyn Error>> {
    let name = package_name(package)?;
    let status = Command::new(nargo)
        .arg("compile")
        .current_dir(package)
        .status()?;
    if !status.success() {
        return Err(format!("nargo compile failed for {}: {status}", package.display()).into());
    }
    let path = package.join("target").join(format!("{name}.json"));
    let json = serde_json::from_slice(&std::fs::read(&path)?)?;
    Ok((path, json))
}

fn validate_l2_key(
    dir: &Path,
    references: &[L2Reference],
    derived: &str,
    check: bool,
) -> Result<(), Box<dyn Error>> {
    let frozen = ["circuit.vk", "bytecode.b64", "abi.json"]
        .iter()
        .any(|name| dir.join(name).exists());
    let stored = match std::fs::read(dir.join("circuit.vk")) {
        Ok(key) => Some(keccak_hex(&key)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    for reference in references {
        if check || reference.stable {
            match reference.pin.as_deref() {
                Some(pin) => {
                    if pin != derived {
                        return Err(format!("VK differs from pinned vk_hash {pin}: derived {derived}; declare a new package path and chain version for stable key changes").into());
                    }
                    if stored.as_deref().is_some_and(|stored| stored != pin) {
                        return Err(
                            format!("stored circuit.vk differs from pinned vk_hash {pin}").into(),
                        );
                    }
                    if check && stored.is_none() {
                        return Err("missing frozen circuit.vk".into());
                    }
                }
                None if check || frozen => {
                    return Err("missing vk_hash pin; only a new, unfrozen package may initialize a stable pin".into());
                }
                None => {}
            }
        }
    }
    Ok(())
}

fn refresh_l2(dir: &Path, json: &serde_json::Value, vk: &[u8]) -> Result<(), Box<dyn Error>> {
    std::fs::write(
        dir.join("bytecode.b64"),
        json["bytecode"].as_str().ok_or("missing bytecode")?,
    )?;
    std::fs::write(dir.join("abi.json"), serde_json::to_vec(&json["abi"])?)?;
    std::fs::write(dir.join("circuit.vk"), vk)?;
    Ok(())
}

fn update_l2_pins(doc: &mut DocumentMut, references: &[L2Reference], hash: &str) {
    for reference in references {
        let chain = doc["l2_chain"]
            .as_array_of_tables_mut()
            .unwrap()
            .get_mut(reference.chain)
            .unwrap();
        let version = chain["versions"]
            .as_array_of_tables_mut()
            .unwrap()
            .get_mut(reference.version)
            .unwrap();
        let circuit = version["circuits"]
            .as_array_mut()
            .unwrap()
            .get_mut(reference.circuit)
            .unwrap();
        circuit
            .as_inline_table_mut()
            .unwrap()
            .insert("vk_hash", hash.into());
    }
}

fn record_version(circuit: &mut Table, version: &str, supersede: Option<(usize, String)>) {
    let versions = circuit
        .entry("versions")
        .or_insert(Item::ArrayOfTables(ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .expect("[[circuit.versions]] array");
    if let Some((idx, hash)) = supersede {
        let old = versions.get_mut(idx).expect("active version");
        old["status"] = value("deprecated");
        old["circuit_hash"] = value(hash);
    }
    let mut release = Table::new();
    release["version"] = value(version);
    release["status"] = value("active");
    versions.push(release);
}

/// Owns only this newly created, per-process scratch directory.
struct Scratch(PathBuf);

impl Scratch {
    fn new(parent: &Path) -> std::io::Result<Self> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        std::fs::create_dir_all(parent)?;
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("xtask-freeze-check-{}-{id}", std::process::id()));
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
        let path = entry.path();
        if name == "target" || name == "abi.json" || name == "bytecode.b64" || name == "circuit.vk"
        {
            continue;
        }
        let to = dst.join(name);
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("cannot copy symlink into scratch: {}", path.display()),
            ));
        }
        if kind.is_dir() {
            copy_noir(&path, &to)?;
        } else {
            std::fs::copy(path, to)?;
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
fn reconcile_artifacts(doc: &mut DocumentMut, canonical: &Path) {
    for circuit in doc
        .get_mut("circuit")
        .and_then(Item::as_array_of_tables_mut)
        .into_iter()
        .flat_map(|circuits| circuits.iter_mut())
    {
        let artifacts = canonical
            .join("resources/circuits")
            .join(circuit["module"].as_str().expect("circuit module"));
        let Some(versions) = circuit
            .get_mut("versions")
            .and_then(Item::as_array_of_tables_mut)
        else {
            continue;
        };
        for version in versions.iter_mut() {
            let status = version["status"].as_str().expect("version status");
            if status == "active" {
                continue;
            }
            let revoked = status == "revoked";
            let dir = artifacts.join(version["version"].as_str().expect("version"));
            if version.get("circuit_hash").is_none() {
                if let Ok(b64) = std::fs::read_to_string(dir.join("bytecode.b64")) {
                    if let Ok(acir) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                        version["circuit_hash"] = value(keccak_hex(&acir));
                    }
                }
            }

            let _ = std::fs::remove_file(dir.join("bytecode.b64"));
            let _ = std::fs::remove_file(dir.join("abi.json"));
            if revoked {
                let _ = std::fs::remove_file(dir.join("circuit.vk"));
                let _ = std::fs::remove_dir(&dir); // succeeds only if now empty
            }
        }
    }
}

/// Write a frozen version dir: `bytecode.b64`, `abi.json`, and `circuit.vk`
/// (derived via `bb write_vk -t evm-no-zk`).
fn write_version(dir: &Path, bytecode_b64: &str, abi_str: &str, bb: &Path, json_path: &Path) {
    std::fs::create_dir_all(dir).expect("mkdir version dir");
    std::fs::write(dir.join("bytecode.b64"), bytecode_b64).expect("write bytecode.b64");
    std::fs::write(dir.join("abi.json"), abi_str).expect("write abi.json");

    let tmp = dir.join(".bb");
    let produced = write_vk(bb, json_path, &tmp).expect("derive verification key");
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

    #[test]
    fn grouped_l1_releases_preserve_identity_and_retire_artifacts() {
        let scratch = Scratch::new(&std::env::temp_dir()).unwrap();
        let mut doc: DocumentMut = r#"
[[circuit]]
module = "moved"

[[circuit]]
module = "retired"

[[circuit.versions]]
version = "1.0.0"
status = "revoked"
"#
        .parse()
        .unwrap();
        let acir = b"frozen ACIR";
        let hash = keccak_hex(acir);
        let abi = serde_json::json!({"parameters": []});
        let vk = b"frozen VK";
        for relative in [
            "resources/circuits/moved/1.0.0",
            "resources/circuits/moved/1.0.1",
            "resources/circuits/retired/1.0.0",
        ] {
            let dir = scratch.0.join(relative);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("bytecode.b64"),
                base64::engine::general_purpose::STANDARD.encode(acir),
            )
            .unwrap();
            std::fs::write(dir.join("abi.json"), abi.to_string()).unwrap();
            std::fs::write(dir.join("circuit.vk"), vk).unwrap();
        }

        let circuit = doc["circuit"]
            .as_array_of_tables_mut()
            .unwrap()
            .get_mut(0)
            .unwrap();
        // The first release must work without a pre-existing versions array.
        record_version(circuit, "1.0.0", None);
        record_version(circuit, "1.0.1", Some((0, hash.clone())));
        reconcile_artifacts(&mut doc, &scratch.0);

        let circuits = doc["circuit"].as_array_of_tables().unwrap();
        let versions = circuits.get(0).unwrap()["versions"]
            .as_array_of_tables()
            .unwrap();
        let old = versions.get(0).unwrap();
        assert_eq!(old["status"].as_str(), Some("deprecated"));
        assert_eq!(old["circuit_hash"].as_str(), Some(hash.as_str()));
        assert_eq!(versions.get(1).unwrap()["status"].as_str(), Some("active"));
        let old_dir = scratch.0.join("resources/circuits/moved/1.0.0");
        assert_eq!(std::fs::read(old_dir.join("circuit.vk")).unwrap(), vk);
        assert!(!old_dir.join("bytecode.b64").exists());
        assert!(!old_dir.join("abi.json").exists());
        assert!(check_version(
            &scratch.0.join("resources/circuits/moved/1.0.1"),
            &hash,
            &abi,
            vk,
        )
        .is_ok());
        let revoked = circuits.get(1).unwrap()["versions"]
            .as_array_of_tables()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(revoked["circuit_hash"].as_str(), Some(hash.as_str()));
        assert!(!scratch.0.join("resources/circuits/retired/1.0.0").exists());
    }

    #[test]
    fn stable_reference_protects_shared_package_even_after_mutable_reference() {
        let scratch = Scratch::new(&std::env::temp_dir()).unwrap();
        let package = scratch.0.join("l2/7/tribute-2");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("Nargo.toml"), "[package]\nname = 'tribute'\n").unwrap();
        let pin = keccak_hex(b"original VK");
        std::fs::write(package.join("circuit.vk"), b"original VK").unwrap();
        let mut doc: DocumentMut = format!(
            r#"
[[l2_chain]]
chain_id = 7
[[l2_chain.versions]]
version = "1.0.0"
stable = false
circuits = [{{path = "tribute-2", vk_hash = "{pin}"}}]
[[l2_chain.versions]]
version = "2.0.0"
stable = true
circuits = [{{path = "tribute-2", vk_hash = "{pin}"}}]
"#
        )
        .parse()
        .unwrap();
        let catalog = catalog(&doc, &scratch.0).unwrap();
        let references = &catalog.l2[0].references;
        assert!(
            validate_l2_key(&package, references, &keccak_hex(b"replacement VK"), false).is_err()
        );

        // Stable means the key, not the ABI spelling or prover bytecode.
        let compiled = serde_json::json!({
            "bytecode": "cmVmYWN0b3JlZA==",
            "abi": {"parameters": [{"name": "renamed_field"}]}
        });
        validate_l2_key(&package, references, &pin, false).unwrap();
        refresh_l2(&package, &compiled, b"original VK").unwrap();
        update_l2_pins(&mut doc, references, &pin);
        assert_eq!(
            std::fs::read_to_string(package.join("bytecode.b64")).unwrap(),
            "cmVmYWN0b3JlZA=="
        );
        let abi: serde_json::Value =
            serde_json::from_slice(&std::fs::read(package.join("abi.json")).unwrap()).unwrap();
        assert_eq!(abi, compiled["abi"]);
        assert_eq!(
            std::fs::read(package.join("circuit.vk")).unwrap(),
            b"original VK"
        );
        validate_l2_key(&package, references, &pin, true).unwrap();
        let versions = doc["l2_chain"]
            .as_array_of_tables()
            .unwrap()
            .get(0)
            .unwrap()["versions"]
            .as_array_of_tables()
            .unwrap();
        assert_eq!(
            versions
                .iter()
                .map(|version| version["version"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["1.0.0", "2.0.0"]
        );
    }

    #[test]
    fn stable_pin_initialization_requires_an_unfrozen_package() {
        let scratch = Scratch::new(&std::env::temp_dir()).unwrap();
        let references = [L2Reference {
            chain: 0,
            version: 0,
            circuit: 0,
            stable: true,
            pin: None,
        }];
        let hash = keccak_hex(b"first VK");
        validate_l2_key(&scratch.0, &references, &hash, false).unwrap();
        assert!(validate_l2_key(&scratch.0, &references, &hash, true).is_err());
        for artifact in ["bytecode.b64", "abi.json", "circuit.vk"] {
            std::fs::write(scratch.0.join(artifact), b"existing frozen artifact").unwrap();
            assert!(validate_l2_key(&scratch.0, &references, &hash, false).is_err());
            std::fs::remove_file(scratch.0.join(artifact)).unwrap();
        }
    }
}
