# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project shape

Rust workspace (version `0.11.0`, edition 2021) for the Outbe zero-knowledge protocol: pluggable consensus primitives, a Noir/barretenberg proving backend, and a frozen, versioned canonical circuit registry. Members:

- `crates/outbe-protocol` — Generic, pluggable consensus primitives. The curve / hash / signature / KDF are swappable `Suite` parameters; `OutbeV1` is the production selection (BN254 / Grumpkin / Poseidon2 / Schnorr, `DOMAIN = 1`). Hashing routes through **`outbe-poseidon`** (git dep, tag `v0.11.0`). `rlib`. Optional `alloy` feature adds field-encoding impls for alloy ABI scalars.
- `crates/outbe-protocol-derive` — `#[derive(Entity)]` proc-macro. Per-field `#[outbe(...)]` roles (`id_seed` / `id_body` / `body` / `owner` / `skip` / `limbed` / `pos = N`) generate the canonical entity-hash preimage. Exercised by the protocol crate's tests.
- `crates/outbe-zk-backend` — Noir proving backend: a shared ACVM witness-solving core plus a barretenberg (UltraHonkKeccak, FFI) prover/verifier. Generic over any circuit implementing the `outbe-protocol` zk seams (`Circuit` / `CircuitId` / `CircuitSuite`). `publish = false` (consumes noir git deps + native libs). Feature `with-network-srs` (on by default) pulls `reqwest` for the Aztec SRS download fallback; `default-features = false` is the offline/mobile build.
- `crates/outbe-zk-canonical` — Concrete canonical circuit/witness types **and** the in-code, append-only, versioned circuit registry. Builds from committed frozen artifacts (no git/noir deps), so it ships to crates.io and `cargo build` is deterministic with or without the noir toolchain. `INCLUSION_DEPTH = 32`.
- `xtask/` — Circuit tooling: `cargo xtask test-circuits` runs every Noir package; `cargo xtask freeze-circuits` is the only command that runs `bb` or writes frozen artifacts.

### How the canonical registry works (`outbe-zk-canonical`)

`build.rs` is **read-only** — it does **not** run `nargo`/`bb`. It reads:

- `circuits/manifest.toml` — append-only registry index: a global `proof_system` (the bb pin, `bb-keccak-v1`) plus one `[[circuit]]` per `(module, version)` with `label`, `status` (`active` / `deprecated` / `revoked`), and a preserved `circuit_hash` once bytecode is dropped.
- `resources/circuits/<module>/<version>/` — frozen, immutable artifacts: `bytecode.b64` (ACIR, active only), `abi.json` (drives the Rust witness types, active only), `circuit.vk` (kept while not revoked).

and emits into `outbe_zk_canonical::noir`: a `pub mod <module>` for the latest **active** version of each circuit (Witness / PublicInputs types + `Circuit<S>`/`CircuitId` impls + identity consts) and `pub const CIRCUIT_REGISTRY: &[RegistryEntry]` over **every** non-revoked version (VK-only verification view). Identity is cryptographic: `circuit_hash = keccak256(decode(bytecode.b64))`, `vk_hash = keccak256(circuit.vk)` — **labels do not affect either hash**.

### Noir sub-projects under `crates/outbe-zk-canonical/noir/`

Sibling Nargo packages (each its own `Nargo.toml`):

| Directory | Nargo name | Type | Role |
|-----------|-----------|------|------|
| `outbe-circuit-core/` | `outbe_circuit_core` | lib | Shared `ownership`, `inclusion`, and `hash` modules. Depends on `noir-lang/schnorr` v0.2.0; Poseidon2 uses the stdlib permutation. |
| `outbe-ownership-circuit/` | `ownership_proof` | bin | Single-NFT ownership proof. |
| `outbe-full-circuit/` | `full_proof` | bin | Ownership + depth-32 Merkle inclusion. |
| `outbe-flat-aggregation-circuit-n{1,2,4,8,16,32,64}/` | `flat_aggregation_n{N}` | bin | Aggregates N ownership proofs. |
| `outbe-emit-mint-circuit/` | `emit_mint` | bin | Contains all Emit-specific formulas plus mint, nullifier, membership, and optional change constraints. |

The ownership / full / aggregation bins pull shared logic from `outbe_circuit_core` via a relative path dep, so editing the lib forces a recompile of those bins at freeze time. Emit owns its protocol formulas locally and imports only generic hashing and Merkle inclusion from the core. `nargo` is pinned to **1.0.0-beta.22** and `bb` to **5.0.0-nightly.20260522** (see `mise.toml`); these must match the noir git tag in `outbe-zk-backend` and the `barretenberg-rs` pin, or freeze-derived VKs won't match the FFI verifier.

## Build commands

Plain cargo works for everything and needs **no** Noir toolchain — `outbe-zk-canonical` builds from its committed frozen artifacts:

- `cargo build --workspace` / `cargo test --workspace` / `cargo fmt` / `cargo clippy` — standard.
- First build compiles the bundled barretenberg C++ FFI (several minutes; not hung). Subsequent builds cache it.

The Noir toolchain is needed **only** to evolve circuits. Install the pinned versions via `mise run install:zk-toolchain` (nargo + bb). `cargo xtask` is aliased in `.cargo/config.toml`.

## Circuit-change workflow

Released circuit versions are frozen; editing the `.nr` sources changes nothing by itself. To mint a new version:

1. `cargo xtask freeze-circuits` — compiles the head noir sources via `nargo`, derives VKs via `bb`, and for each circuit whose **ACIR changed** mints a new frozen version under `resources/circuits/` and records it `active` in `manifest.toml` (superseded version → `deprecated`, its `circuit_hash` preserved, bytecode/abi dropped, VK kept).
   - unchanged ACIR → skipped; changed ACIR + same ABI → patch bump; ABI change → pass `--abi-change` (minor) or `--semantic` (major + new `DOMAIN` decision).
2. Review and commit the minted `resources/circuits/` artifacts **and** the modified `circuits/manifest.toml` **together** — the PR review is the audit gate for admitting a circuit. Status transitions (active → deprecated → revoked) are manifest edits reconciled by the next freeze.

## Dependency pinning

The noir git deps (`acir` / `acvm` / `bn254_blackbox_solver`, tag `v1.0.0-beta.22`) stay **inline** in `outbe-zk-backend`, not in `[workspace.dependencies]`. `barretenberg-rs` is exact-pinned (`=5.0.0-nightly.20260522`). `outbe-poseidon` is a tagged git dep until published. Bump the noir tag, the bb pin, and the version in mise.toml together. `deny.toml` allows exactly two git origins: `noir-lang/noir` and `outbe/outbe-poseidon`.

## Profiles and test gotchas

- `[profile.dev]` is `opt-level = 3` deliberately — proving is unusably slow otherwise. Don't "fix" this.
- `outbe-zk-backend`'s proving roundtrip tests (`tests/barretenberg.rs`) and benches (`benches/proving.rs`, the n1–n64 tiers) build the barretenberg FFI and download/cache the SRS; each tier proof takes tens of seconds. The fast suites — `outbe-protocol` and `outbe-zk-canonical` tests — read frozen artifacts and need neither the toolchain nor the network.

## Style

- Standard `rustfmt` (no custom `rustfmt.toml`).
- `outbe-zk-canonical`'s `noir` registry is generated/frozen — never hand-edit `resources/circuits/` or the `build.rs` codegen output; mint via `cargo xtask freeze-circuits`.
