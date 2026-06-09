# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project shape

Rust workspace producing zero-knowledge circuits (Noir) and a barretenberg-rs FFI prover. Three library crates plus an `xtask` build orchestrator:

- `crates/outbe-zk-circuit-noir` — Noir circuits + FFI prover. Crate-type is `[staticlib, cdylib, rlib]` (serves iOS, Android, and desktop Rust callers simultaneously).
- `crates/outbe-zk-canonical` — Pure-static canonical VK + circuit-hash data. Zero deps beyond `hex-literal`. **Generated**, not hand-written.
- `crates/outbe-crypto-common` — Witness types, Poseidon formulas, consensus-binding primitives.
- `xtask/` — Build orchestration. Single file (`xtask/src/main.rs`).

### Noir sub-projects under `crates/outbe-zk-circuit-noir/`

Three sibling Nargo packages (each with its own `Nargo.toml`), not a single `circuits/` directory:

| Directory                  | Nargo name            | Type | Role                                                                              |
|----------------------------|-----------------------|------|-----------------------------------------------------------------------------------|
| `outbe-circuit-core/`      | `outbe_circuit_core`  | lib  | Shared modules `ownership` + `inclusion`. Depends on `noir-lang/poseidon` v0.3.0 and `noir-lang/schnorr` v0.2.0. |
| `outbe-ownership-circuit/` | `ownership_proof`     | bin  | sec.4.2 single-NFT ownership proof. Public inputs: `[owner, nft_hash]`.           |
| `outbe-full-circuit/`      | `full_proof`          | bin  | Ownership + depth-8 Merkle inclusion. Public inputs: `[owner, nft_hash, expected_merkle_root]`. |

Both bin crates pull the ownership/inclusion logic from `outbe_circuit_core` via a relative path dep — there is **one** ownership implementation (`outbe_circuit_core::ownership::verify_ownership_per_su`) shared across both circuits, so editing the lib forces a recompile of both bins and (per the canonical workflow) a regen of `outbe-zk-canonical`.

Compiled bytecodes land in `crates/outbe-zk-circuit-noir/data/` as `full_proof.json` and `ownership_proof.json`. `nargo` itself is pinned to **1.0.0-beta.22** (install via `noirup -v 1.0.0-beta.22`); `xtask` refuses to compile under any other version because the canonical VKs are tied to that compiler's output.

## Build commands — always go through xtask

`cargo xtask` is aliased in `.cargo/config.toml`. Use these, not raw `cargo build` / `nargo compile`, for anything circuit-related:

- `cargo xtask compile-circuits` — Compile all Noir circuits via nargo, write bytecodes to `data/`.
- `cargo xtask regenerate-canonical` — Derive UltraHonkKeccak VKs + circuit hashes via the noir_rs FFI path and write them into `outbe-zk-canonical`.
- `cargo xtask regenerate-canonical --check` — Verify canonical data is in sync without writing. Use this to detect drift before committing.

Standard `cargo test` / `cargo check` / `cargo fmt` work normally for everything else.

## Circuit-change workflow

When Noir circuits change, the canonical commit must contain all three artifacts together:

1. `cargo xtask compile-circuits` — regenerate `data/` bytecodes
2. `cargo xtask regenerate-canonical` — regenerate VKs + circuit hashes in `outbe-zk-canonical`
3. Commit `data/` **and** the modified `crates/outbe-zk-canonical/` files in the **same** commit as the circuit change

The `--check` variant catches drift. Run it before pushing if unsure.

## Vendored noir_rs — read-only

`crates/outbe-zk-circuit-noir/src/vendor/noir_rs/` is ~821 LOC of vendored upstream noir_rs proving glue (Apache-2.0; see `NOTICE.md`). **Do not modify these files.** Diverging breaks FFI proof compatibility with the canonical VKs. If you think a change is needed there, escalate to the human — don't edit.

The pinned `acvm` / `acvm_blackbox_solver` / `bn254_blackbox_solver` / `nargo` / `barretenberg-rs` deps in the workspace `Cargo.toml` exist specifically to satisfy this vendored code. Bump them together when chasing a noir release, not individually.

## Profiles and test gotchas

- `[profile.dev]` is set to `opt-level = 3` deliberately — proving is unusably slow otherwise. Don't "fix" this.
- The `aggregation-full-tiers` feature on `outbe-zk-circuit-noir` gates expensive tier prove+verify tests. Each tier takes tens of seconds; N=64 takes several minutes. Off by default; only enable when explicitly exercising tier proving.
- First `cargo xtask` build triggers the barretenberg-rs C++ FFI build, which takes several minutes. It is not hung — let it finish. Subsequent builds cache it.

## Style

- Standard `rustfmt` (no custom `rustfmt.toml`).
- Follow existing module patterns in each crate — `outbe-zk-canonical` in particular is generated; do not hand-edit it (use `regenerate-canonical`).
