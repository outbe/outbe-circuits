//! `cargo xtask` — canonical-circuit tooling.
//!
//! `test-circuits` runs every vendored Noir package and every non-revoked L2
//! root through `nargo test`.
//!
//! `freeze-circuits` compiles the head Noir sources under
//! `outbe-zk-canonical/noir/` and mints frozen L1 versions — see [`l1`].
//! `freeze-circuits --check` is the same compile as a dry run: it asserts that
//! each committed `active` artifact's ACIR, `abi.json` and `circuit.vk`
//! reproduce, writing nothing outside `target/`.
//!
//! `l2 verify` / `l2 admit` work the other side of the gate: they prove a
//! committed L2 verification key came from its committed source, and mint a
//! registry entry from a root — see [`l2`].
//!
//! Layout: [`toolchain`] locates `nargo`/`bb` and asserts the `mise.toml`
//! pins, [`noir`] runs them, [`l1`] writes only under `outbe-zk-canonical` and
//! `target/`, [`l2`] only under `outbe-l2-zk-canonical` and `target/`.

// `xtask` is a CLI binary; stdout/stderr is its interface.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod l1;
mod l2;
mod noir;
mod toolchain;

use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("freeze-circuits") => l1::freeze(&args.collect::<Vec<_>>()),
        Some("test-circuits") => l1::test_circuits(),
        Some("l2") => {
            let sub = args.next();
            let rest = args.collect::<Vec<_>>();
            match sub.as_deref() {
                Some("verify") => l2::verify(&rest),
                Some("admit") => l2::admit(&rest),
                other => {
                    eprintln!("unknown l2 subcommand {other:?}");
                    usage();
                }
            }
        }
        other => {
            eprintln!("unknown command {other:?}");
            usage();
        }
    }
}

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  cargo xtask freeze-circuits [--check | --abi-change | --semantic]");
    eprintln!("  cargo xtask test-circuits");
    eprintln!("  cargo xtask l2 verify [--root PATH | --changed [--base REF] | --all]");
    eprintln!("  cargo xtask l2 admit --root PATH");
    std::process::exit(2);
}

/// Workspace root = the xtask crate's parent directory.
pub(crate) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}
