//! Locating `nargo` and `bb`, and asserting they are the versions the
//! workspace pins in `mise.toml`.
//!
//! A verification key reproduces only under the pinned toolchain, so every
//! command that *asserts* a committed key reproduces calls [`assert_pinned`]
//! and refuses to run with anything else: `l2 verify`, `l2 admit`, and
//! `freeze-circuits --check` (`l1.rs`, which branches on the `--check` flag).
//! A plain `freeze-circuits` keeps the looser locate-only path ([`nargo`] /
//! [`bb`]) on purpose — it is minting a new version, not asserting that an old
//! one still reproduces.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate a tool via `$ENV`, then `$HOME/<home_rel>`, then PATH.
pub fn locate(env_var: &str, home_rel: &str, bin: &str) -> Option<PathBuf> {
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

pub fn nargo() -> PathBuf {
    locate("NARGO", ".nargo/bin/nargo", "nargo").expect("nargo not found (set $NARGO)")
}

pub fn bb() -> PathBuf {
    locate("BB", ".bb/bb", "bb").expect("bb not found (set $BB)")
}

/// The `mise.toml` pin for `[tools.<tool>] version`.
fn pin(tool: &str) -> Result<String, String> {
    let path = crate::workspace_root().join("mise.toml");
    let doc: toml_edit::DocumentMut = std::fs::read_to_string(&path)
        .map_err(|e| format!("mise.toml: {e}"))?
        .parse()
        .map_err(|e| format!("mise.toml: parse error: {e}"))?;
    doc["tools"][tool]["version"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("mise.toml: [tools.{tool}] version missing"))
}

/// `<bin> --version`, first line, trimmed.
fn version_of(bin: &Path) -> Result<String, String> {
    let out = Command::new(bin)
        .arg("--version")
        .output()
        .map_err(|e| format!("spawn {}: {e}", bin.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.lines().next().unwrap_or("").trim().to_string())
}

/// Locate both tools and assert their versions equal the `mise.toml` pins.
/// Returns `(nargo, bb)`. This runs once, before any compile.
pub fn assert_pinned() -> Result<(PathBuf, PathBuf), String> {
    let (nargo_pin, bb_pin) = (pin("nargo")?, pin("bb")?);
    let (nargo, bb) = (nargo(), bb());

    // `nargo --version` prints `nargo version = 1.0.0-beta.22` plus build info.
    let got = version_of(&nargo)?;
    if !got.contains(&nargo_pin) {
        return Err(format!(
            "{} --version says {got:?}; the mise.toml pin is nargo {nargo_pin} \
             — an L2 key reproduces only under the pinned toolchain",
            nargo.display()
        ));
    }
    // `bb --version` prints the bare version.
    let got = version_of(&bb)?;
    if got != bb_pin {
        return Err(format!(
            "{} --version says {got:?}; the mise.toml pin is bb {bb_pin} \
             — an L2 key reproduces only under the pinned toolchain",
            bb.display()
        ));
    }
    Ok((nargo, bb))
}
