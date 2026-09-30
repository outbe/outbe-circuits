# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project shape

Rust workspace (version `0.26.0`, edition 2021) for the Outbe zero-knowledge protocol: concrete consensus cryptography, a Noir/barretenberg proving backend, and a frozen, versioned canonical circuit registry. Members:

- `crates/outbe-protocol` — Concrete BN254 / Grumpkin / Poseidon2 / Schnorr consensus primitives. Exposes `Fr`, module-level formulas in `primitive::hash`, and concrete entity/signer/Merkle types under the existing module paths. No `Suite` or `OutbeV1` selector remains. Owns the verifier envelope and combined-proof validation; concrete circuit layouts stay downstream. Hashing routes through **`outbe-poseidon`**. `rlib`. Optional `alloy` feature adds field-encoding impls for alloy ABI scalars.
- `crates/outbe-protocol-derive` — `#[derive(Entity)]` proc-macro. Per-field `#[outbe(...)]` roles (`id_seed` / `id_body` / `body` / `owner` / `skip` / `limbed` / `pos = N`) generate the canonical entity-hash preimage. Exercised by the protocol crate's tests.
- `crates/outbe-zk-backend` — Noir proving backend: a shared ACVM witness-solving core plus a barretenberg (UltraHonkKeccak, FFI) prover/verifier, generic over the `outbe-protocol` ZK seams. `publish = false` (consumes noir git deps + native libs). Feature `with-network-srs` (on by default) pulls `reqwest` for the Aztec SRS download fallback; `default-features = false` is the offline/mobile build.
- `crates/outbe-zk-canonical` — Concrete circuit/witness types, DemoTribute/Emit/Paynote/PaynoteMerge combined-proof decoders, append-only L1 releases, and VK-pinned L2 chain-version selections. Builds from committed artifacts without Noir dependencies/tooling. `INCLUSION_DEPTH = 32`.
- `xtask/` — Circuit tooling: `cargo xtask test-circuits` tests catalog packages; `cargo xtask freeze-circuits` mints L1 releases or refreshes permitted L2 packages; `--check` reproduces L1 artifacts and L2 pinned VKs without committed writes.

### How the canonical registry works (`outbe-zk-canonical`)

`build.rs` is **read-only** — it does **not** run `nargo`/`bb`. It reads:

- `circuits/manifest.toml` — L1 `[[circuit]]` entries contain `module`, `label`, and nested append-only `[[circuit.versions]]` records. L1 sources default to `noir/<module>/`, artifacts to `resources/circuits/<module>/<version>/`; no path fields. Global `proof_system` and shared `libraries` remain.
- L2 `[[l2_chain]]` entries contain `chain_id` and nested `[[l2_chain.versions]]` records: chain `version`, `stable`, and `circuits = [{path, vk_hash}]`. Paths are relative to `l2/<chain_id>/`; each package directly contains `Nargo.toml`, `src/`, `abi.json`, `bytecode.b64`, and `circuit.vk`. No independent L2 artifact release history or duplicate global declaration.

`noir::CIRCUIT_REGISTRY` contains non-revoked L1 releases. `l2_circuits(chain_id, version) -> &'static [&'static L2Circuit]` selects an exact array of shared private descriptors (`path`, `vk_hash`, `vk_bytes`), without per-chain Rust modules or an implicit latest fallback. Typed modules keep circuit-specific names from Nargo; their descriptive L2 `VERSION` is the latest chain version selecting that package. L2 admission pins `keccak256(circuit.vk)`. `stable = true` protects verification identity, not source spelling/ABI names; any stable reference protects a shared package. Demo stays mutable at chain `57005`, version `1.0.0`; Niflheim is stable at `9900501`, version `1.0.0`. Do not restore the obsolete Demo artifact-version bindings.

### Noir sub-projects in `crates/outbe-zk-canonical/`

Nargo packages (each its own `Nargo.toml`), with paths relative to the canonical crate. Both testing and freezing use the catalog, not a second hardcoded package list.

| Directory | Nargo name | Type | Role |
|-----------|-----------|------|------|
| `noir/outbe-circuit-core/` | `outbe_circuit_core` | lib | Shared `ownership`, `merkle_tree`, `hash`, `tags` (base purpose tags, combined with a per-circuit domain via `tags::tag`), and `types` modules. Depends on `noir-lang/schnorr` v0.2.0; Poseidon2 uses the stdlib permutation. |
| `noir/outbe-paynote-lib/` | `paynote_lib` | lib | Shared Paynote hashing and Merkle formulas for spend and merge circuits. |
| `noir/ownership_proof/` | `ownership_proof` | bin | Single-NFT ownership proof. |
| `l2/57005/tribute/` | `demo_tribute` | bin | Demo Tribute ownership + depth-32 Merkle inclusion. |
| `noir/emit_mint/` | `emit_mint` | bin | Contains all Emit-specific formulas plus mint, nullifier, membership, and optional change constraints. Amounts are 256-bit (`noir-lang/noir-bignum` `U256`, tag `v0.10.0`). |
| `noir/paynote/` | `paynote` | bin | Private ERC20 payment note: bearer spend authority by key knowledge, 256-bit `noir-lang/noir-bignum` amounts, asset-bound commitment, nullifier, membership, and optional change. |
| `noir/paynote_merge/` | `paynote_merge` | bin | Merge existing Paynotes into a single note. |
| `l2/9900501/tribute/` | `niflheim_tribute` | bin | Self-contained Niflheim Tribute ownership and depth-32 Merkle inclusion proof. |

The ownership / Demo Tribute bins pull shared logic from `outbe_circuit_core` via a relative path dep, so editing the lib forces a recompile of those bins at freeze time. Niflheim Tribute keeps its ownership and inclusion helpers in its own source. Emit owns its protocol formulas locally and imports only generic hashing and Merkle inclusion from the core. Paynote and Paynote Merge share `paynote_lib`; keep both shared libraries in the catalog for testing and scratch reproduction. `nargo` is pinned to **1.0.0-beta.22** and `bb` to **5.0.0-nightly.20260522** (see `mise.toml`); these must match the noir git tag in `outbe-zk-backend` and the `barretenberg-rs` pin, or freeze-derived VKs won't match the FFI verifier.

## Build commands

Plain cargo works for everything and needs **no** Noir toolchain — `outbe-zk-canonical` builds from its committed frozen artifacts:

- `cargo build --workspace` / `cargo test --workspace` / `cargo fmt` / `cargo clippy` — standard.
- First build compiles the bundled barretenberg C++ FFI (several minutes; not hung). Subsequent builds cache it.

The Noir toolchain is needed only to evolve circuits or check their reproducibility. Install the pinned versions via `mise install nargo bb`. `cargo xtask` is aliased in `.cargo/config.toml`.

## Circuit-change workflow

Editing sources does not update the committed proving artifacts by itself.

1. `cargo xtask freeze-circuits` compiles catalog packages with `nargo` and derives VKs with `bb`.
   - L1: unchanged ACIR/ABI → skipped; changed ACIR with same ABI → patch release; ABI change requires `--abi-change` or `--semantic`. Superseded releases become deprecated and retain their VK/hash.
   - L2: stable packages must reproduce their pinned VK; unchanged-key source/ABI changes may refresh flat prover artifacts. Mutable packages may refresh VKs and pins in place. Chain versions never auto-bump. A stable key change requires a new package and explicit chain-version entry. A new unfrozen package may omit its pin until first freeze; an existing frozen stable package may not.
2. Commit source, frozen artifacts, and manifest together. L1 status transitions are reconciled by normal freezing; L2 has chain stability instead of active/deprecated/bound/unbound states.

`cargo xtask freeze-circuits --check` (also `mise run freeze-circuits:check`) asserts tool versions, compiles scratch copies, compares full L1 ACIR/ABI/VK and L2 committed/derived VKs against pins, then cleans up. L2 ABI-only/source-spelling edits are allowed if VK identity stays unchanged. No manifest/artifact/compiler-output writes occur. CI uses this mode; do not combine it with bump flags.

## Dependency pinning

The noir git deps (`acir` / `acvm` / `bn254_blackbox_solver`, tag `v1.0.0-beta.22`) stay **inline** in `outbe-zk-backend`, not in `[workspace.dependencies]`. `barretenberg-rs` is exact-pinned (`=5.0.0-nightly.20260522`). `outbe-poseidon` is a tagged git dep until published. Bump the noir tag, the bb pin, and the version in mise.toml together. `deny.toml` allows exactly two git origins: `noir-lang/noir` and `outbe/outbe-poseidon`.

## Profiles and test gotchas

- `[profile.dev]` is `opt-level = 3` deliberately — proving is unusably slow otherwise. Don't "fix" this.
- `outbe-zk-backend`'s proving roundtrip tests (`tests/barretenberg.rs`) and benches (`benches/proving.rs`) build the barretenberg FFI and download/cache the SRS. The fast suites — `outbe-protocol` and `outbe-zk-canonical` tests — read frozen artifacts and need neither the toolchain nor the network.

## Style

- Standard `rustfmt` (no custom `rustfmt.toml`).
- Never hand-edit frozen artifact bytes, VK pins, or build-generated output. Use `cargo xtask freeze-circuits`; artifact roots are `resources/circuits/` for L1 and flat `l2/<chain_id>/<package>/` for L2.
