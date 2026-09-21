//! Running the Noir toolchain: `nargo compile` in a package directory, `bb
//! write_vk` on its artifact, and the keccak the circuit hash is made of.
//!
//! Shared by [`crate::l1`] (which compiles in place on a freeze, and a scratch
//! copy of the whole `noir/` tree on `--check`) and [`crate::l2`] (which always
//! compiles a scratch copy, so a committed root never gains an untracked
//! `target/`).

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use tiny_keccak::{Hasher, Keccak};

/// Owns a scratch build directory under `target/`. Constructed *before* the
/// copy is made, so every exit path after that point — a `nargo`/`bb` failure,
/// a later `?`, a panic — drops it and removes the directory. A scratch copy is
/// a build artifact, never a diagnostic: anything worth keeping is written
/// beside it, not into it.
///
/// `std::process::exit` does not run destructors, so a caller that exits rather
/// than returns still sweeps explicitly before exiting.
pub struct Scratch(pub PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub struct Compiled {
    /// `<dir>/target/<package>.json`, the input `bb write_vk -b` wants.
    pub json_path: PathBuf,
    /// Base64 ACIR, exactly as nargo emitted it.
    pub bytecode_b64: String,
    /// The decoded ACIR; `keccak_hex` of this is the circuit hash.
    pub acir: Vec<u8>,
    /// The `abi` object of the artifact.
    pub abi: serde_json::Value,
}

/// Run `nargo compile` in `dir` and read `target/<package>.json`.
pub fn compile(nargo: &Path, dir: &Path, package: &str) -> Result<Compiled, String> {
    let st = Command::new(nargo)
        .arg("compile")
        .current_dir(dir)
        .status()
        .map_err(|e| format!("spawn nargo in {}: {e}", dir.display()))?;
    if !st.success() {
        return Err("nargo compile failed".to_string());
    }

    let json_path = dir.join("target").join(format!("{package}.json"));
    let text = std::fs::read_to_string(&json_path)
        .map_err(|_| format!("nargo produced no target/{package}.json"))?;
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", json_path.display()))?;
    let bytecode_b64 = json["bytecode"]
        .as_str()
        .ok_or("compiled artifact has no `bytecode`")?
        .to_string();
    let acir = base64::engine::general_purpose::STANDARD
        .decode(&bytecode_b64)
        .map_err(|e| format!("bytecode is not base64: {e}"))?;

    Ok(Compiled {
        json_path,
        bytecode_b64,
        acir,
        abi: json["abi"].clone(),
    })
}

/// Run `bb write_vk -t evm-no-zk` and return the key bytes. `scratch` is a
/// directory bb writes a file literally named `vk` into; it is removed again.
pub fn write_vk(bb: &Path, json_path: &Path, scratch: &Path) -> Result<Vec<u8>, String> {
    std::fs::create_dir_all(scratch).map_err(|e| format!("mkdir {}: {e}", scratch.display()))?;
    let st = Command::new(bb)
        .arg("write_vk")
        .arg("-b")
        .arg(json_path)
        .arg("-o")
        .arg(scratch)
        .args(["-t", "evm-no-zk"])
        .status()
        .map_err(|e| format!("spawn bb: {e}"))?;
    if !st.success() {
        return Err("bb write_vk failed".to_string());
    }
    let produced = scratch.join("vk");
    let vk = std::fs::read(&produced).map_err(|_| "bb produced no vk".to_string())?;
    let _ = std::fs::remove_dir_all(scratch);
    Ok(vk)
}

/// Recursive copy skipping `target/`. Both sides compile a scratch copy: an
/// L2 root must not gain an untracked `target/`, and the L1 dry run must not
/// rewrite the tracked `noir/<pkg>/target/<module>.json`.
pub fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "target" {
            continue;
        }
        let (from, to) = (entry.path(), dst.join(&name));
        if entry.file_type()?.is_dir() {
            copy_dir(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// keccak256 -> lower-case hex (no `0x`).
pub fn keccak_hex(bytes: &[u8]) -> String {
    let mut h = Keccak::v256();
    h.update(bytes);
    let mut o = [0u8; 32];
    h.finalize(&mut o);
    o.iter().map(|b| format!("{b:02x}")).collect()
}
