# outbe-circuits

Rust workspace for the **Outbe zero-knowledge protocol**: concrete BN254/Grumpkin consensus primitives, a Noir + barretenberg proving backend, and a frozen, versioned canonical circuit registry.

## Crates

| Crate | What it is |
|-------|------------|
| [`outbe-protocol`](crates/outbe-protocol) | Concrete BN254 / Grumpkin / Poseidon2 / Schnorr consensus primitives. Module-level formulas live in `primitive::hash`; entity, signer, circuit and backend interfaces remain extensible. Hashing routes through [`outbe-poseidon`](https://github.com/outbe/outbe-poseidon). |
| [`outbe-protocol-derive`](crates/outbe-protocol-derive) | `#[derive(Entity)]` — maps a typed struct's `#[outbe(...)]`-annotated fields to the canonical entity-hash preimage. |
| [`outbe-zk-backend`](crates/outbe-zk-backend) | Noir proving backend: an ACVM witness solver plus a barretenberg (UltraHonkKeccak, FFI) prover/verifier. Generic over any circuit implementing the `outbe-protocol` zk seams. |
| [`outbe-zk-canonical`](crates/outbe-zk-canonical) | Concrete circuit/witness types, append-only L1 releases, and VK-pinned L2 chain-version selections. Builds from committed artifacts — ships to crates.io, no Noir toolchain required. |
| `xtask` | Circuit tooling: `cargo xtask test-circuits`, `cargo xtask freeze-circuits`, and the read-only `cargo xtask freeze-circuits --check`. |

## Build

Plain cargo works for everything and needs **no** Noir toolchain — `outbe-zk-canonical` builds from its committed frozen artifacts:

```bash
cargo build --workspace
cargo test  --workspace           # fast suites: outbe-protocol + outbe-zk-canonical
cargo test  -p outbe-zk-backend   # barretenberg proving round-trips (builds the C++ FFI; downloads SRS)
```

The first build compiles the bundled barretenberg C++ FFI (several minutes — not hung). `[profile.dev]` is `opt-level = 3` deliberately; proving is unusably slow otherwise.

## Circuits

The catalog in `crates/outbe-zk-canonical/circuits/manifest.toml` contains four active L1 circuits and two L2 chain registrations. Paths below are relative to that crate:

| Directory | Nargo name | Type | Role |
|-----------|-----------|------|------|
| `noir/outbe-circuit-core/` | `outbe_circuit_core` | lib | Shared `ownership`, `inclusion`, and `hash` modules. Depends on `noir-lang/schnorr` v0.2.0; Poseidon2 via the stdlib permutation. |
| `noir/outbe-paynote-lib/` | `paynote_lib` | lib | Shared Paynote hashing and Merkle formulas used by spend and merge circuits. |
| `noir/ownership_proof/` | `ownership_proof` | bin | Single-NFT ownership proof. |
| `l2/57005/tribute/` | `demo_tribute` | bin | Demo Tribute ownership + depth-32 Merkle inclusion. |
| `noir/emit_mint/` | `emit_mint` | bin | Contains all Emit-specific formulas plus mint, nullifier, membership, and optional change constraints. |
| `noir/paynote/` | `paynote` | bin | Private ERC20 payment note with 256-bit amounts, bearer spend authority by key knowledge, asset-bound commitment, nullifier, membership, and optional change. |
| `noir/paynote_merge/` | `paynote_merge` | bin | Merge existing Paynotes into a single note. |
| `l2/9900501/tribute/` | `niflheim_tribute` | bin | Self-contained Niflheim Tribute ownership and depth-32 Merkle inclusion proof. |

L1 uses conventional source and artifact paths: `noir/<module>/` and `resources/circuits/<module>/<version>/`. L2 chain versions select arrays of package paths with pinned `vk_hash` values; each package stores `abi.json`, `bytecode.b64`, and `circuit.vk` directly under `l2/<chain_id>/<package>/`. `outbe_zk_canonical::l2_circuits(chain_id, version)` returns the exact selection's package/key descriptors without per-chain Rust modules. Demo uses mutable chain version `1.0.0`; Niflheim uses stable `1.0.0`.

### Toolchain

The Noir toolchain is needed only to evolve circuits or check their reproducibility, pinned via `mise`:

```bash
mise install nargo bb    # nargo 1.0.0-beta.22 + bb 5.0.0-nightly.20260522
```

`cargo xtask` is aliased in `.cargo/config.toml`.

### Circuit-change workflow

```bash
cargo xtask freeze-circuits          # mint L1 releases / refresh permitted L2 artifacts
```

For L1, changed ACIR or ABI mints a release and appends an active `[[circuit.versions]]` record; the previous release becomes deprecated and keeps its VK. ABI changes require `--abi-change` (minor) or `--semantic` (major + new domain decision).

For L2, `[[l2_chain.versions]]` selects a package array and declares `stable`. Stable versions pin **verification identity only**: comments, refactoring, and ABI renames may be refreshed if the VK is unchanged. A different stable key requires a new package and an explicitly declared chain version. Mutable versions can refresh their artifacts and pins in place. Freezing never automatically bumps chain versions. New packages may omit their pin until the first freeze, but an existing frozen stable package cannot remove its pin to bypass protection. Commit source, artifacts, and manifest together.

To check without minting or changing committed files:

```bash
cargo xtask freeze-circuits --check
# or: mise run freeze-circuits:check
```

The check requires the exact `nargo` and `bb` versions pinned in `mise.toml`.
It compiles catalog packages in a per-process scratch tree under `target/`.
L1 checks compare decoded bytecode, structural ABI, and a freshly derived VK;
L2 checks require committed and derived VKs to match the manifest pins. L2 ABI
or source spelling changes alone do not fail verification. A mismatch exits
nonzero; scratch files are cleaned up
on success or failure. The manifest, frozen artifacts, and tracked Noir compiler
outputs remain unchanged. CI uses this mode. `--check` cannot be combined with
`--abi-change` or `--semantic`.

## License

MIT. See [`LICENSE`](LICENSE).
