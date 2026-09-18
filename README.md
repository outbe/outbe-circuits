# outbe-circuits

Rust workspace for the **Outbe zero-knowledge protocol**: concrete BN254 cryptographic primitives, a Noir + barretenberg proving backend, and two frozen, versioned circuit registries — one for L1 circuits, one for the keys registered L2 networks prove their claims under.

## Crates

| Crate | What it owns |
|-------|--------------|
| [`outbe-zk-core`](crates/outbe-zk-core) | The cryptographic core: BN254 as the proving field, Grumpkin as its embedded curve, Poseidon2 as the hash, Grumpkin Schnorr as the signature. Codec, hash formulas, the inclusion tree, keys, the `Entity` trait, the circuit seams, the verifier-wire decoders. Every formula is a plain function over `ark_bn254::Fr`. |
| [`outbe-zk-core-derive`](crates/outbe-zk-core-derive) | `#[derive(Entity)]` — reads the canonical entity-hash preimage off a struct's `#[outbe(...)]` field roles. Re-exported as `outbe_zk_core::Entity`. |
| [`outbe-zk-backend`](crates/outbe-zk-backend) | Noir proving backend: an ACVM witness solver plus a barretenberg (UltraHonkKeccak, FFI) prover/verifier, generic over the core's `Circuit` seam. `publish = false`. |
| [`outbe-zk-canonical`](crates/outbe-zk-canonical) | **L1 side.** The `emit_mint` and `paynote` statements, their Rust hash mirrors and combined-proof decoders, and the append-only frozen circuit registry under `circuits/manifest.toml` + `resources/circuits/`. |
| [`outbe-l2-claims`](crates/outbe-l2-claims) | **L2 contract.** The claim entities and their bindings, the claim public-input ABIs, and the generated `PublicInputs`. Holds **no verification key**, so a consumer that only folds claims takes this and nothing moves in its binary when an L2 registers. |
| [`outbe-l2-zk-canonical`](crates/outbe-l2-zk-canonical) | **L2 registry.** The committed L2 circuit roots with their verification keys, `l2/manifest.toml`, the `l2_keys` table and the key-aware `decode_public_inputs`. Depends on `outbe-l2-claims`; the edge runs one way. |
| [`outbe-l2-demo`](examples/outbe-l2-demo) | The reference L2: the Rust side of the tribute root registered under chain 57005 — `Witness` generated from the root's ABI, `prove_tribute`, and a prove-and-verify round trip against the registered key. `publish = false`. |
| `xtask` | The only code that runs `nargo` or `bb`. `publish = false`. |

Dependency direction: five of the eight members depend on `outbe-zk-core` — `outbe-zk-canonical`, `outbe-l2-claims`, `outbe-l2-zk-canonical`, `outbe-zk-backend` and `outbe-l2-demo`. The other three do not: `outbe-zk-core-derive` is a proc-macro crate whose only dependencies are `syn`, `quote` and `proc-macro2` (it emits `::outbe_zk_core::` paths into the caller's crate, which is not a dependency edge), and `xtask` depends on no workspace member at all — that is why it can run `nargo`/`bb` without pulling barretenberg into the build. `outbe-zk-core` itself depends on nothing in the workspace but the derive crate. **The two canonical crates have no dependency on each other in either direction** (check their `Cargo.toml` files), so an L2 registration cannot touch an L1 circuit, its key or its hash mirrors, and an L1 freeze cannot change what an L2 key verifies. On the L2 side the split between `outbe-l2-claims` and `outbe-l2-zk-canonical` is a one-way edge — registry depends on claims — and that direction is itself a guarantee: no verification key can reach the binary of a consumer that depends on `outbe-l2-claims` alone, under any cargo invocation. `outbe-l2-zk-canonical` also takes `outbe-l2-claims` as a **build-dependency**, because a build script cannot read another package's files by path and it needs the claim ABIs to gate every committed root. `examples/outbe-l2-demo` depends on the L2 crate, the core and the backend, and has **no package dependency** on `outbe-zk-canonical` — no Cargo edge, no type, no call. Two of its tests do read committed L1 *files* by path: `tests/proof_system.rs` reads `crates/outbe-zk-canonical/circuits/manifest.toml` to check the two `proof_system` pins agree, and `tests/roundtrip.rs` reads `crates/outbe-zk-canonical/resources/circuits/paynote/1.2.0/circuit.vk` — one pinned L1 circuit version — to show a tribute proof is rejected under a foreign key.

## Build

Plain cargo works for everything and needs **no** Noir toolchain — both canonical crates build from committed artifacts:

```bash
cargo build --workspace
cargo test  --workspace           # includes the proving round trips — see below
```

**`cargo test --workspace` is not the quick, offline suite.** It links `outbe-zk-backend`'s native `barretenberg-rs` dependency, which on a cold cache takes several minutes before any test runs — not hung — and it proves. The tests that prove are `outbe-zk-backend`'s `tests/emit_mint.rs` and `tests/paynote.rs`, and `examples/outbe-l2-demo`'s `tests/roundtrip.rs`. `outbe-zk-backend`'s `tests/crs_init.rs` generates no proof — it calls `init_crs()` twice and asserts that is idempotent — but it still loads the SRS. `benches/proving.rs` is a bench target, so `cargo test` neither builds nor runs it; `cargo bench -p outbe-l2-demo` does both. A bb proof dominates the runtime of any test that makes one, which is why `roundtrip.rs` is one test carrying six assertions rather than six tests each paying for its own proof.

Those tests need the BN254 SRS. `crates/outbe-zk-backend/src/barretenberg/srs.rs` reads **one** path, the first of these that is *set*: the `barretenberg::set_srs_path()` override, then `$BB_CRS_PATH`, then `~/.bb-crs/bn254_g1.dat` (the file `bb` itself caches). There is no fallback from one to the next — setting the override or the variable is what picks the file. It **range-downloads from the Aztec CRS whenever that one file does not yield the points the circuit needs** — missing, unreadable, or shorter than `num_points * 64` bytes — which is what the default `with-network-srs` feature exists for; with `default-features = false` a missing local SRS is a hard error instead. That fetch is not the only network access from a cold checkout: cargo also fetches the tagged git dependencies listed in the workspace `Cargo.toml`.

No test needs `nargo` or `bb`: the only one that shells out to them, `examples/outbe-l2-demo/tests/reproduce.rs`, is `#[ignore]`d, as are the two diagnostic helpers in `outbe-zk-backend/tests/srs_pins.rs`. The suites that read committed artifacts only — no proving, no FFI work beyond linking, no network — are:

```bash
cargo test -p outbe-zk-core -p outbe-zk-canonical -p outbe-l2-claims -p outbe-l2-zk-canonical
cargo test -p outbe-l2-demo --test witness --test proof_system
```

`[profile.dev]` is `opt-level = 3` deliberately; proving is unusably slow otherwise.

The Noir toolchain is needed only to evolve circuits or reproduce keys. Both tools are pinned in one file:

```bash
mise install                     # rust, plus nargo 1.0.0-beta.22 and bb 5.0.0-nightly.20260522, from mise.toml
```

CI installs from the same file with `jdx/mise-action`, but not the same set: the `check` job passes `install_args: nargo`, and only `l2-verify` and `l1-freeze-check` install `nargo bb`. `cargo xtask` is aliased in `.cargo/config.toml`; `mise tasks ls` lists the task wrappers; each one's `run =` line in `mise.toml` is the raw command it shells out to, so a non-mise user can copy it. A task's `description` is a label, not reliably that command, and `check` and `check:keys` run several commands each.

## Two registries

Both are append-only indexes of frozen artifacts, read by a `build.rs` that never runs `nargo` or `bb`. They differ in what a version is and who writes it.

| | L1 — `outbe-zk-canonical` | L2 — `outbe-l2-zk-canonical` |
|---|---|---|
| Index | `circuits/manifest.toml`, one `[[circuit]]` per `(module, version)` | `l2/manifest.toml`, one `[[l2_circuit]]` per `(chain_id, claim, version)` |
| Sources | `noir/` — three sibling Nargo packages in this repo | `l2/<chain_id>/<claim>/<version>/` — one self-contained package per registered L2 |
| Committed artifacts | `bytecode.b64`, `abi.json`, `circuit.vk` under `resources/circuits/<module>/<version>/` | `abi.json`, `circuit.vk`, `circuit.hash` in the root; no bytecode |
| Public-input layout | per circuit, whatever its ABI says | fixed per **claim** by `outbe-l2-claims`'s `claims/<claim>/abi.json`; every root of that claim must match it |
| Who mints a version | a maintainer, via `cargo xtask freeze-circuits` | whoever opens the pull request, via `cargo xtask l2 admit` (or by hand) — nothing ties them to the chain id in the path |
| The gate | `freeze-circuits --check` recompiles every `active` entry and asserts ACIR, ABI and VK reproduce | `l2 verify` recompiles the root and asserts `circuit.vk` and `circuit.hash` reproduce |

The L1 crate has no concept of an L2, and the L2 crate has no concept of an L1 circuit. See [`crates/outbe-zk-canonical/README.md`](crates/outbe-zk-canonical/README.md) for the L1 side and [`crates/outbe-l2-claims/README.md`](crates/outbe-l2-claims/README.md) + [`crates/outbe-l2-zk-canonical/README.md`](crates/outbe-l2-zk-canonical/README.md) for the L2 contract and its registry, and [`examples/outbe-l2-demo`](examples/outbe-l2-demo) for a working prover and the reviewer checklist.

### Noir packages under `crates/outbe-zk-canonical/noir/`

| Directory | Nargo name | Type | Role |
|-----------|-----------|------|------|
| `outbe-circuit-core/` | `outbe_circuit_core` | lib | Shared `merkle_tree`, `hash`, `tags` and `types`. No external deps; Poseidon2 via the stdlib permutation. |
| `outbe-emit-mint-circuit/` | `emit_mint` | bin | Emit formulas plus mint, nullifier, membership and optional change constraints. |
| `outbe-paynote-circuit/` | `paynote` | bin | Private ERC20 payment note: bearer spend authority, 256-bit amounts, asset-bound commitment, nullifier, membership, optional change. |

`outbe_circuit_core` is L1-only: an L2 root may not reach it, because no `path` dependency may resolve outside the root.

## xtask

```
cargo xtask freeze-circuits [--check | --abi-change | --semantic]
cargo xtask test-circuits
cargo xtask l2 verify [--root PATH | --changed [--base REF] | --all]
cargo xtask l2 admit --root PATH
```

- `freeze-circuits` mints L1 versions whose ACIR or ABI changed; `--check` is the dry run that writes nothing outside `target/`. `--abi-change` (minor) / `--semantic` (major) make a public-input-layout change explicit.
- `test-circuits` runs `nargo test` in every L1 Noir package and every non-revoked L2 root.
- `l2 verify` reproduces committed L2 keys from their committed source; `l2 admit` registers a new root.
- Every command that derives a key runs `bb write_vk`, which needs the Aztec CRS: on first use `bb` downloads ~64MB of `bn254_g1.dat` plus ~2MB of `grumpkin_g1.flat.dat` into `~/.bb-crs`. That covers `freeze-circuits` with and without `--check`, `l2 verify` and `l2 admit`; CI caches the directory, keyed on `mise.toml`.
- The three commands that *prove* something — `freeze-circuits --check`, `l2 verify` and `l2 admit` — assert the `mise.toml` tool pins before compiling anything (`xtask/src/toolchain.rs::assert_pinned`); a key that reproduces under an unpinned `bb` proves nothing. A plain `freeze-circuits` and `test-circuits` only locate the tools, since they are minting or testing, not asserting.

## CI

`.github/workflows/ci.yml` runs on three triggers and no others: `pull_request` (any base branch), `push` **restricted to `main`**, and manual `workflow_dispatch`. A push to a topic branch with no open pull request runs nothing. Within a run:

| Job | Runs when | What it does |
|---|---|---|
| `cargo-deny` | every run of the workflow | `cargo deny check all` — all four checks: advisories, bans, licenses and sources (the two git origins `deny.toml` allows). |
| `changes` | every run of the workflow | `dorny/paths-filter` computes the `l1`, `l2` and `toolchain` flags the two key jobs gate on. |
| `check` (stable + beta) | every run, except a **push** whose head commit says `[skip ci]` — the `if:` reads `github.event.head_commit`, which only a push populates, so the opt-out does nothing on a pull request or a `workflow_dispatch` | `cargo fmt --all -- --check`; `cargo clippy --all-targets --all-features` with `-D warnings` and five further `-D` lints and four `-A`s (the exact block is in `ci.yml`, repeated in `mise.toml`'s `check` task); `cargo test --workspace`; `cargo test -p outbe-zk-canonical --features alloy`; `cargo xtask test-circuits`, for which it installs `nargo` only. |
| `l2-verify` | the `l2` filter matched, or any push | `cargo xtask l2 verify --all` on a toolchain change or a push (a push to `main` has no PR base, so `--changed` would select nothing), `--changed` otherwise. |
| `l1-freeze-check` | the `l1` filter matched, or any push | `cargo xtask freeze-circuits --check`, then `git diff --exit-code` to prove the dry run wrote nothing. |

The `l2` filter is `crates/outbe-l2-zk-canonical/l2/**`, `crates/outbe-l2-claims/claims/**`, `mise.toml`, `Cargo.toml` and `crates/outbe-zk-canonical/circuits/manifest.toml` — the L1 manifest is in the list because it holds the `proof_system` the L2 manifest is compared against. The `l1` filter is `crates/outbe-zk-canonical/noir/**`, `crates/outbe-zk-canonical/resources/circuits/**`, `crates/outbe-zk-canonical/circuits/manifest.toml` and `mise.toml` — `dorny/paths-filter` matches against repository-relative paths, so every entry in both filters is spelled from the repository root, never from a crate. A push to `main` is never cancelled by the concurrency group.

## What is machine-checked

Each row names the mechanism, so a failure is traceable to one file.

| Guarantee | Mechanism |
|---|---|
| A `B256` at or above the field modulus is rejected, never reduced | `outbe_zk_core::codec::field_from_be_bytes_canonical` returns `Error::NonCanonical`; `field_from_be_bytes` is the separate, deliberately reducing form. |
| Every registered L2 key came from a committed root | `l2_keys` is a `&'static` table emitted by `crates/outbe-l2-zk-canonical/build.rs`; `L2Key`'s fields are private with read-only accessors and no public constructor. |
| A registered root is self-contained and reproducible | Root hygiene (`type = "bin"`, no `path` dep escaping the root, every git dep carrying `tag` or `rev`) is enforced both in that crate's `build.rs` and in `cargo xtask l2 verify`. |
| A committed L2 key belongs to its committed source | `l2 verify` recompiles the root in a scratch copy under the pinned toolchain and requires `circuit.vk` byte-identical and `circuit.hash == keccak256(ACIR)`. |
| Every root of a claim exposes that claim's public inputs | The root's public ABI is compared to `outbe-l2-claims`'s `claims/<claim>/abi.json` by name, type and order — at build time (through the `CLAIM_ABIS` build-dependency) and again in `l2 verify`. |
| No verification key can reach a claim-only consumer's binary | `outbe-l2-claims` is a separate package that contains no key and depends on no crate that does; the edge to `outbe-l2-zk-canonical` runs the other way. No cargo feature is involved, so no feature unification can defeat it. |
| A committed L1 artifact belongs to its committed `.nr` source | `cargo xtask freeze-circuits --check`, then `git diff --exit-code` in the `l1-freeze-check` job. |
| An L1 circuit's identity is its bytes, not its label | `circuit_hash = keccak256(ACIR)` and `vk_hash = keccak256(VK)`, derived in `crates/outbe-zk-canonical/build.rs`. |
| The L1 and L2 sides pin the same proof system | `proof_system = "bb-keccak-v1"` in both manifests, compared by `xtask l2 verify`/`admit` and by `examples/outbe-l2-demo/tests/proof_system.rs`, which also asserts the `mise.toml` `bb` pin equals the workspace `barretenberg-rs` pin. |
| `cargo build` and `cargo test` need no Noir toolchain | All **four** `build.rs` scripts in the workspace — `crates/outbe-zk-canonical/`, `crates/outbe-l2-claims/`, `crates/outbe-l2-zk-canonical/` and `examples/outbe-l2-demo/` — read committed files only; the one test that shells out to `nargo`/`bb` (`examples/outbe-l2-demo/tests/reproduce.rs`) is `#[ignore]`. |

Not machine-checked, by construction: what an L2 circuit's constraints actually say. That is human review — see the reviewer checklist in [`examples/outbe-l2-demo/README.md`](examples/outbe-l2-demo/README.md).

## License

MIT. See [`LICENSE`](LICENSE).
