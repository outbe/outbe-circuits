//! The committed key reproduces from the committed source.
//!
//! This is the admission gate, run here so an L2 team can check their own root
//! with `cargo test` before opening a pull request. Ignored by default because
//! it is the one test in this crate that needs the Noir toolchain — everything
//! else builds from committed artifacts.
//!
//! CI never runs it: no job in `.github/workflows/ci.yml` passes `--ignored`.
//! Nothing is lost by that — the `l2-verify` job runs the same
//! `cargo xtask l2 verify` command directly, on every change that can move a
//! key — so this stays a convenience for running the gate locally.

use std::process::Command;

#[test]
#[ignore = "needs nargo + bb: run with --ignored"]
fn the_demo_root_reproduces_its_key() {
    let status = Command::new(env!("CARGO"))
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .args([
            "xtask",
            "l2",
            "verify",
            "--root",
            "crates/outbe-l2-zk-canonical/l2/57005/tribute/1.0.0",
        ])
        .status()
        .expect("run cargo xtask");
    assert!(status.success(), "the demo root must reproduce its key");
}
