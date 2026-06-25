# outbe-circuits

Rust workspace for the **Outbe zero-knowledge protocol**: pluggable consensus primitives, a Noir + barretenberg proving backend, and a frozen, versioned canonical circuit registry.

## Crates

| Crate | What it is |
|-------|------------|
| [`outbe-protocol`](crates/outbe-protocol) | Generic, pluggable consensus primitives — curve / hash / signature / KDF are swappable `Suite` parameters. `OutbeV1` is the production selection (BN254 / Grumpkin / Poseidon2 / Schnorr). Hashing routes through [`outbe-poseidon`](https://github.com/outbe/outbe-poseidon). |
| [`outbe-protocol-derive`](crates/outbe-protocol-derive) | `#[derive(Entity)]` — maps a typed struct's `#[outbe(...)]`-annotated fields to the canonical entity-hash preimage. |
| [`outbe-zk-backend`](crates/outbe-zk-backend) | Noir proving backend: an ACVM witness solver plus a barretenberg (UltraHonkKeccak, FFI) prover/verifier. Generic over any circuit implementing the `outbe-protocol` zk seams. |
| [`outbe-zk-canonical`](crates/outbe-zk-canonical) | Concrete canonical circuit/witness types **and** the in-code, append-only, versioned circuit registry. Builds from committed frozen artifacts — ships to crates.io, no Noir toolchain required. |
| `xtask` | Release tooling: `cargo xtask freeze-circuits`. |

## Build

Plain cargo works for everything and needs **no** Noir toolchain — `outbe-zk-canonical` builds from its committed frozen artifacts:

```bash
cargo build --workspace
cargo test  --workspace           # fast suites: outbe-protocol + outbe-zk-canonical
cargo test  -p outbe-zk-backend   # barretenberg proving round-trips (builds the C++ FFI; downloads SRS)
```

The first build compiles the bundled barretenberg C++ FFI (several minutes — not hung). `[profile.dev]` is `opt-level = 3` deliberately; proving is unusably slow otherwise.

## Circuits

The 9 canonical circuits live as sibling Nargo packages under `crates/outbe-zk-canonical/noir/`:

| Directory | Nargo name | Type | Role |
|-----------|-----------|------|------|
| `outbe-circuit-core/` | `outbe_circuit_core` | lib | Shared `ownership` + `inclusion` + `hash2`. Depends on `noir-lang/schnorr` v0.2.0; Poseidon2 via the stdlib permutation. |
| `outbe-ownership-circuit/` | `ownership_proof` | bin | Single-NFT ownership proof. |
| `outbe-full-circuit/` | `full_proof` | bin | Ownership + depth-32 Merkle inclusion. |
| `outbe-flat-aggregation-circuit-n{1,2,4,8,16,32,64}/` | `flat_aggregation_n{N}` | bin | Aggregates N ownership proofs. |

Released circuit versions are **frozen** and committed under `crates/outbe-zk-canonical/resources/circuits/`; a circuit's cryptographic identity is `circuit_hash = keccak256(ACIR)` and `vk_hash = keccak256(VK)`. Editing the `.nr` sources changes nothing by itself.

### Toolchain

The Noir toolchain is needed **only** to evolve circuits, pinned via `mise`:

```bash
mise run install:zk-toolchain    # nargo 1.0.0-beta.22 + bb 5.0.0-nightly.20260522
```

`cargo xtask` is aliased in `.cargo/config.toml`.

### Circuit-change workflow

```bash
cargo xtask freeze-circuits          # the only step that runs nargo/bb
```

For each circuit whose **ACIR changed**, it mints a new frozen version under `resources/circuits/` and records it `active` in `circuits/manifest.toml` (the superseded version is set `deprecated`, keeping only its VK). Pass `--abi-change` (minor) or `--semantic` (major + new `DOMAIN` decision) when the public-input layout changes. Commit the minted artifacts **and** the modified `manifest.toml` together with the `.nr` source change — the PR review is the audit gate.

## License

MIT. See [`LICENSE`](LICENSE).
