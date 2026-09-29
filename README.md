# outbe-circuits

Rust workspace for the **Outbe zero-knowledge protocol**: concrete BN254/Grumpkin consensus primitives, a Noir + barretenberg proving backend, and a frozen, versioned canonical circuit registry.

## Crates

| Crate | What it is |
|-------|------------|
| [`outbe-protocol`](crates/outbe-protocol) | Concrete BN254 / Grumpkin / Poseidon2 / Schnorr consensus primitives. Module-level formulas live in `primitive::hash`; entity, signer, circuit and backend interfaces remain extensible. Hashing routes through [`outbe-poseidon`](https://github.com/outbe/outbe-poseidon). |
| [`outbe-protocol-derive`](crates/outbe-protocol-derive) | `#[derive(Entity)]` — maps a typed struct's `#[outbe(...)]`-annotated fields to the canonical entity-hash preimage. |
| [`outbe-zk-backend`](crates/outbe-zk-backend) | Noir proving backend: an ACVM witness solver plus a barretenberg (UltraHonkKeccak, FFI) prover/verifier. Generic over any circuit implementing the `outbe-protocol` zk seams. |
| [`outbe-zk-canonical`](crates/outbe-zk-canonical) | Concrete canonical circuit/witness types **and** the in-code, append-only, versioned circuit registry. Builds from committed frozen artifacts — ships to crates.io, no Noir toolchain required. |
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

The five active canonical circuits live as sibling Nargo packages under `crates/outbe-zk-canonical/noir/`:

| Directory | Nargo name | Type | Role |
|-----------|-----------|------|------|
| `outbe-circuit-core/` | `outbe_circuit_core` | lib | Shared `ownership`, `inclusion`, and `hash` modules. Depends on `noir-lang/schnorr` v0.2.0; Poseidon2 via the stdlib permutation. |
| `outbe-ownership-circuit/` | `ownership_proof` | bin | Single-NFT ownership proof. |
| `demo-tribute/` | `demo_tribute` | bin | Demo Tribute ownership + depth-32 Merkle inclusion. |
| `outbe-emit-mint-circuit/` | `emit_mint` | bin | Contains all Emit-specific formulas plus mint, nullifier, membership, and optional change constraints. |
| `outbe-paynote-circuit/` | `paynote` | bin | Private ERC20 payment note with 256-bit amounts, bearer spend authority by key knowledge, asset-bound commitment, nullifier, membership, and optional change. |
| `niflheim-tribute/` | `niflheim_tribute` | bin | Self-contained Niflheim Tribute ownership and depth-32 Merkle inclusion proof. |

Released circuit versions are **frozen** and committed under `crates/outbe-zk-canonical/resources/circuits/`; a circuit's cryptographic identity is `circuit_hash = keccak256(ACIR)` and `vk_hash = keccak256(VK)`. Editing the `.nr` sources changes nothing by itself.

### Toolchain

The Noir toolchain is needed only to evolve circuits or check their reproducibility, pinned via `mise`:

```bash
mise install nargo bb    # nargo 1.0.0-beta.22 + bb 5.0.0-nightly.20260522
```

`cargo xtask` is aliased in `.cargo/config.toml`.

### Circuit-change workflow

```bash
cargo xtask freeze-circuits          # mint versions and write frozen artifacts
```

For each circuit whose **ACIR changed**, it mints a new frozen version under `resources/circuits/` and records it `active` in `circuits/manifest.toml` (the superseded version is set `deprecated`, keeping only its VK). Pass `--abi-change` (minor) or `--semantic` (major + new `DOMAIN` decision) when the public-input layout changes. Commit the minted artifacts **and** the modified `manifest.toml` together with the `.nr` source change — the PR review is the audit gate.

To check without minting or changing committed files:

```bash
cargo xtask freeze-circuits --check
# or: mise run freeze-circuits:check
```

The check requires the exact `nargo` and `bb` versions pinned in `mise.toml`.
It compiles all five circuits in a per-process scratch copy under `target/`,
compares decoded bytecode and structural ABI, and always re-derives and compares
each verification key. A mismatch exits nonzero; scratch files are cleaned up
on success or failure. The manifest, frozen artifacts, and tracked Noir compiler
outputs remain unchanged. CI uses this mode. `--check` cannot be combined with
`--abi-change` or `--semantic`.

## License

MIT. See [`LICENSE`](LICENSE).
