# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project shape

Rust workspace (version `0.11.0`, edition 2021) for the Outbe zero-knowledge protocol: concrete BN254 cryptographic primitives, a Noir/barretenberg proving backend, and **two** frozen, versioned registries — L1 circuits in `outbe-zk-canonical`, L2 claim keys in `outbe-l2-zk-canonical`. Six library crates, one example and xtask:

- `crates/outbe-zk-core` — The concrete cryptographic core: BN254 field, Grumpkin curve, Poseidon2 hash, Grumpkin Schnorr. Modules `codec` / `error` / `hash` / `imt` / `keys` / `shielded_pool` / `entity` / `zk` / `zkproof`. Every formula is a plain function over `ark_bn254::Fr`, re-exported as `outbe_zk_core::Fr`. Owns the verifier envelope and combined-proof validation; concrete circuit layouts stay downstream. Hashing routes through **`outbe-poseidon`** (git dep, tag `v0.11.0`). Optional `alloy` feature adds field-encoding impls for alloy ABI scalars (the orphan rule forces them here). Re-exports `#[derive(Entity)]`. `#![forbid(unsafe_code)]`.
- `crates/outbe-zk-core-derive` — `#[derive(Entity)]` proc-macro. Exactly five per-field `#[outbe(...)]` roles — `id` / `body` / `pos = N` / `limbed` / `skip` — generate the canonical entity-hash preimage. Every field must carry one. Emits `::outbe_zk_core::` paths; exercised by `outbe-zk-core`'s `tests/limbed.rs` and `tests/sorted_set.rs`.
- `crates/outbe-zk-backend` — Noir proving backend: a shared ACVM witness-solving core plus a barretenberg (UltraHonkKeccak, FFI) prover/verifier, generic over the `outbe-zk-core` ZK seams. `publish = false` (consumes noir git deps + native libs). Feature `with-network-srs` (on by default) pulls `reqwest` for the Aztec SRS download fallback; `default-features = false` is the offline/mobile build.
- `crates/outbe-zk-canonical` — **L1 side.** Concrete canonical circuit/witness types, circuit-specific Emit/Paynote combined-proof decoders, and the in-code append-only versioned circuit registry. Builds from committed frozen artifacts (no git/noir deps), so it ships to crates.io and `cargo build` is deterministic with or without the noir toolchain.
- `crates/outbe-l2-claims` — **The L1-to-L2 contract.** The claim entities (`claims::tribute::TributeDraftClaim`) and their `binding` formulas, the claim public-input ABIs under `claims/<claim>/abi.json`, and a `build.rs` that emits the per-claim `PublicInputs` / `public_words` / `from_fields` / `alloy` mirror plus `CLAIM_ABIS`. **Contains no verification key and depends on no crate that does** — that is the whole point of it being a separate package. No tree depth and no tree domain: those are each root's own (`BINDING_DOMAIN` in `claims::tribute`, folded into `binding`, is the claim's own and lives here).
- `crates/outbe-l2-zk-canonical` — **L2 registry.** The committed L2 circuit roots + verification keys under `l2/<chain_id>/<claim>/<version>/`, `l2/manifest.toml`, and a `build.rs` that emits `enum Claim`, the `&'static` `l2_keys(chain_id, claim)` table and the key-aware `decode_public_inputs(combined, vk)`. Depends on `outbe-l2-claims` (normal **and** build dependency) and re-exports it as `claims::<name>`.
- `examples/outbe-l2-demo` — **The reference L2.** The Rust side of the registered root `l2/57005/tribute/1.0.0`: a `build.rs` that generates `Witness` + the `CircuitId` impl from the root's committed `abi.json` / `circuit.vk` / `circuit.hash`, `prove_tribute` (the witness builder), an L2-side `TributeDraft` showing the projection onto `TributeDraftClaim`, and the tests that prove against the registered key. `publish = false`. Carries its own copy of the root's ACIR (`resources/bytecode.b64`, tied to `circuit.hash` at build time) because L2 roots deliberately commit no bytecode. No package dependency on `outbe-zk-canonical`; two tests read committed L1 files by path — `tests/proof_system.rs` the L1 manifest, `tests/roundtrip.rs` the pinned `paynote/1.2.0/circuit.vk` as a foreign key.
- `xtask/` — The only code that runs `nargo` or `bb`. `src/main.rs` dispatches; `src/toolchain.rs` locates the tools and asserts their versions equal the `mise.toml` pins; `src/noir.rs` holds the scratch-copy and keccak helpers; `src/l1.rs` (`CIRCUITS = emit_mint, paynote`) writes frozen artifacts only under `crates/outbe-zk-canonical/`, and on the `--check` path writes nothing there at all — it compiles a scratch copy of the whole `noir/` tree under `target/xtask-l1-check-<pid>/` instead; `src/l2.rs` writes only under `crates/outbe-l2-zk-canonical/` (plus scratch copies under `target/xtask-l2/`), but reads three files outside it: `crates/outbe-l2-claims/claims/<claim>/abi.json`, the claim ABI a root's public parameters are checked against; `crates/outbe-zk-canonical/circuits/manifest.toml`, for the `proof_system` comparison in `assert_toolchain`; and `mise.toml`, through the `toolchain::assert_pinned` it calls. Dependencies: `serde_json`, `base64`, `tiny-keccak`, `toml_edit`.

```
cargo xtask freeze-circuits [--check | --abi-change | --semantic]
cargo xtask test-circuits
cargo xtask l2 verify [--root PATH | --changed [--base REF] | --all]
cargo xtask l2 admit --root PATH
```

**The two canonical crates do not depend on each other, in either direction.** An L2 registration cannot touch an L1 circuit, its key or its hash mirrors; an L1 freeze cannot change what an L2 key verifies. They share only `outbe-zk-core` and `outbe-zk-backend`.

### How the canonical registry works (`outbe-zk-canonical`)

`build.rs` is **read-only** — it does **not** run `nargo`/`bb`. It reads:

- `circuits/manifest.toml` — append-only registry index: a global `proof_system` (the bb pin, `bb-keccak-v1`) plus one `[[circuit]]` per `(module, version)` with `label`, `status` (`active` / `deprecated` / `revoked`), and a preserved `circuit_hash` once bytecode is dropped.
- `resources/circuits/<module>/<version>/` — frozen, immutable artifacts: `bytecode.b64` (ACIR, active only), `abi.json` (drives the Rust witness types, active only), `circuit.vk` (kept while not revoked).

and emits into `outbe_zk_canonical::noir`: a `pub mod <module>` for the latest **active** version of each circuit (Witness / PublicInputs types + `Circuit`/`CircuitId` impls + identity consts) and `pub const CIRCUIT_REGISTRY: &[RegistryEntry]` over **every** non-revoked version (VK-only verification view). Identity is cryptographic: `circuit_hash = keccak256(decode(bytecode.b64))`, `vk_hash = keccak256(circuit.vk)` — **labels do not affect either hash**.

### How the L2 side splits (`outbe-l2-claims` + `outbe-l2-zk-canonical`)

The claim contract and the key registry are **two packages**, and the dependency runs one way: registry → claims. That is a structural guarantee, not a cargo feature — a consumer that only folds claims (a prover, a TEE image whose identity is a measurement over its own bytes) depends on `outbe-l2-claims`, and no verification key can reach its binary under any cargo invocation. It used to be a default-on `l2-keys` feature on one crate; cargo unifies features across the selected package set, so `--bin` selection from the workspace root, a bare workspace build and a stale shared-target artifact each defeated it. Do not reintroduce a feature here.

`outbe-l2-claims`'s `build.rs` reads `claims/<claim>/abi.json` and **nothing else** — no key, no root, no manifest. The ABI is the public half of a Noir ABI document and nothing more; `tribute` is four field words, `owner, nft_hash, binding_hash, merkle_root`. A breaking change to that list is a **new claim name**, not a new version. It emits per claim `PUBLIC_INPUT_COUNT` / `PublicInputs` / `public_words` / `from_fields` / an `alloy` mirror, plus `CLAIM_ABIS`: each claim's `abi.json` as an `include_str!`'d `&'static str` with its word count.

`outbe-l2-zk-canonical`'s `build.rs` is **read-only** too — no `nargo`/`bb`. It reads:

- `outbe_l2_claims::CLAIM_ABIS` — the claim ABIs, read from the crate that owns them. A build script cannot open another package's files by path, so `outbe-l2-claims` is a `[build-dependencies]` entry as well as a `[dependencies]` one, and the contract arrives as a const.
- `l2/manifest.toml` — append-only: a global `proof_system` (`bb-keccak-v1`, must equal the L1 pin) plus one `[[l2_circuit]]` per `(chain_id, claim, version)` with `status` and a crate-relative `root`.
- `<root>/abi.json` and `<root>/circuit.vk` — the compiled ABI and the key L1 verifies with. Bytecode is not committed; `xtask l2 verify` regenerates it.

and emits into `outbe_l2_zk_canonical::generated` (re-exported through the crate root): `enum Claim`, `claims::<name>` — the contract glob-re-exported from `outbe-l2-claims` plus `CLAIM` and `decode_public_inputs(combined, vk)` — and `L2_KEYS` + `l2_keys(chain_id, claim)`. `decode_public_inputs` takes the **key**, not a baked `COMBINED_LEN`: the length comes from the key header, so one decoder serves every registered key, and that key dependency is why it lives here rather than with the claim. The layout arithmetic (`proof_words`, `combined_len`, `encode_combined_proof`) is hand-written once in `src/lib.rs`, not generated per claim.

Build-time hard failures: a root missing `Nargo.toml` / `abi.json` / `circuit.vk`; root hygiene (`type = "bin"`, a `path` dependency resolving outside the root, a git dependency without `tag`/`rev`); the root's public ABI differing from the claim ABI by name, type or order; a key that is not 59 words or whose header does not declare `PUBLIC_INPUT_COUNT + 8` public inputs; a duplicate `(chain_id, claim, version)`; a bad `status`; a `revoked` entry whose root still exists; a missing or drifted `proof_system`. Every message names the offending entry. What it cannot check — that the committed key came from the committed source — is `cargo xtask l2 verify`'s job, which repeats the hygiene rules under the toolchain.

`L2Key`'s fields are private with read-only accessors (`version()` / `status()` / `vk_hash()` / `vk_bytes()`) and it has no public constructor, so every key a consumer can reach came from a committed root. Both crates re-export `outbe_zk_core`; the registry also re-exports `outbe_l2_claims`, so a verifier needs one dependency and a claim-only consumer takes `outbe-l2-claims` instead.

### Noir sub-projects under `crates/outbe-zk-canonical/noir/`

Sibling Nargo packages (each its own `Nargo.toml`):

| Directory | Nargo name | Type | Role |
|-----------|-----------|------|------|
| `outbe-circuit-core/` | `outbe_circuit_core` | lib | Shared `merkle_tree`, `hash`, `tags` (base purpose tags, combined with a per-circuit domain via `tags::tag`), and `types` modules. No external deps; Poseidon2 uses the stdlib permutation. |
| `outbe-emit-mint-circuit/` | `emit_mint` | bin | Contains all Emit-specific formulas plus mint, nullifier, membership, and optional change constraints. Amounts are 256-bit (`noir-lang/noir-bignum` `U256`, tag `v0.10.0`). |
| `outbe-paynote-circuit/` | `paynote` | bin | Private ERC20 payment note: bearer spend authority by key knowledge, 256-bit `noir-lang/noir-bignum` amounts, asset-bound commitment, nullifier, membership, and optional change. |

Both bins pull shared hashing/Merkle logic from `outbe_circuit_core` via a relative path dep, so editing the lib forces a recompile at freeze time. Emit owns its protocol formulas locally and imports only generic hashing and Merkle inclusion from the core. `nargo` is pinned to **1.0.0-beta.22** and `bb` to **5.0.0-nightly.20260522** (see `mise.toml`); these must match the noir git tag in `outbe-zk-backend` and the `barretenberg-rs` pin, or freeze-derived VKs won't match the FFI verifier.

## Build commands

Plain cargo works for everything and needs **no** Noir toolchain — `outbe-zk-canonical` builds from its committed frozen artifacts:

- `cargo build --workspace` / `cargo test --workspace` / `cargo fmt` / `cargo clippy` — standard.
- The first build of `outbe-zk-backend` links its native `barretenberg-rs` dependency and takes several minutes on a cold cache (not hung). Subsequent builds reuse it.

The Noir toolchain is needed **only** to evolve circuits. Install the pinned versions with `mise install` (nargo + bb, from `mise.toml`; CI uses the same file via `jdx/mise-action`). `cargo xtask` is aliased in `.cargo/config.toml`.

## Circuit-change workflow

Released circuit versions are frozen; editing the `.nr` sources changes nothing by itself. To mint a new version:

1. `cargo xtask freeze-circuits` — compiles the head noir sources via `nargo`, derives VKs via `bb`, and for each circuit whose **ACIR or ABI changed** mints a new frozen version under `resources/circuits/` and records it `active` in `manifest.toml` (superseded version → `deprecated`, its `circuit_hash` preserved, bytecode/abi dropped, VK kept).
   - unchanged ACIR and ABI → skipped; changed ACIR + same ABI → patch bump; ABI change → pass `--abi-change` (minor) or `--semantic` (major + new `DOMAIN` decision).
2. Review and commit the minted `resources/circuits/` artifacts **and** the modified `circuits/manifest.toml` **together** — the PR review is the audit gate for admitting a circuit. Status transitions (active → deprecated → revoked) are manifest edits reconciled by the next freeze.
3. `cargo xtask freeze-circuits --check` proves it: the same compile and key derivation as a freeze, asserted against the committed `active` artifacts, writing nothing outside `target/`. It asserts the `mise.toml` pins first, compiles a scratch copy of the whole `noir/` tree (the two tracked `noir/<pkg>/target/<module>.json` — `outbe-emit-mint-circuit/target/emit_mint.json` and `outbe-paynote-circuit/target/paynote.json` — must come back byte-identical), and reports every failing module before exiting 1. CI runs it in the `l1-freeze-check` job.

## L2 registration workflow

An L2 is admitted by a pull request that adds one circuit root plus its `[[l2_circuit]]` entry; CI recompiles the root and asserts the key reproduces byte for byte.

1. The L2 writes `crates/outbe-l2-zk-canonical/l2/<chain_id>/<claim>/<version>/{Nargo.toml,src/main.nr}`. Root hygiene is enforced: `type = "bin"`, git deps pinned by `tag` or `rev`, and **no `path` dependency leaving the root** — `outbe_circuit_core` is L1-only and not importable from `l2/`.
2. `cargo xtask l2 admit --root <path>` derives `(chain_id, claim, version)` from the path itself — there are no `--chain`/`--claim`/`--version` flags, and the path must be `l2/<chain_id>/<claim>/<version>` with a three-part version. It refuses a triple or a root string the manifest already has, and refuses a root that already holds `abi.json` / `circuit.vk` / `circuit.hash` (a merged root is immutable — bump the version). It compiles in a scratch copy, checks the **compiled** ABI against the claim ABI, writes the three artifacts into the root, appends one `[[l2_circuit]]` entry with `status = "active"` through `toml_edit`, and prints the `verify` command to run next. An L2 may skip it and commit the three files by hand.
3. `cargo xtask l2 verify [--root PATH | --changed [--base REF] | --all]` proves it. Order (`xtask/src/l2.rs`): load the manifest, reject a duplicate `(chain_id, claim, version)` and any `revoked` entry whose root still exists, select; assert the toolchain **once**, before any root (`nargo`/`bb` equal to the `mise.toml` pins, and the L2 manifest's `proof_system` equal to the L1 manifest's); then per root — hygiene, committed `abi.json` vs `outbe-l2-claims`'s `claims/<claim>/abi.json`, then the scratch compile, then committed ABI == compiled ABI (structural `serde_json::Value`, not a string compare; on mismatch the compiled ABI is dumped beside the scratch copy for diffing), then `circuit.vk` byte-identical, then `circuit.hash == keccak256(ACIR)`. Everything cheap runs before `nargo`, so a tooling failure never masks a defect a file read would have named.
4. A merged root is pinned to its **key**, not frozen as bytes: it may change only where the compiled ACIR and `circuit.vk` stay byte-identical (a comment, a `#[test]` — Noir excludes tests from the binary's ACIR), and `verify` is what establishes that, not the claim. A constraint fix moves the key, so it is a new version directory and entry (old one → `deprecated`); a different public-input list is a different **claim**, not a version.

`--changed` selects an entry when its own root or its claim ABI (in `crates/outbe-l2-claims/claims/`) moved, or when the manifest gained an **added** `root = "..."` line (`select` / `added_roots` — a status-only manifest edit selects nothing extra). A change to `mise.toml`, the workspace `Cargo.toml` or `crates/outbe-zk-canonical/circuits/manifest.toml` (`TOOLCHAIN_FILES`) widens it to every live entry, because those are the only things that can stop an untouched key reproducing. A key is a deterministic function of the compiled ACIR and the `bb` version; the ACIR is a deterministic function of the root's source, its tag-pinned dependencies and the `nargo` version. Both tools are pinned once, in `mise.toml`, with no per-entry pin — so a toolchain bump runs `--all`.

Never hand-edit a committed root's `abi.json` / `circuit.vk` / `circuit.hash`, and never commit a root's `target/`. `l2 verify` and `l2 admit` compile a scratch copy under `target/xtask-l2/` and leave the root alone, but `cargo xtask test-circuits` runs `nargo test` in the root itself — `nargo` has no `--target-dir` — so it does write `<root>/target/`. That path is gitignored; it is a build artifact, not something to commit or hand-edit.

## Dependency pinning

The noir git deps (`acir` / `acvm` / `bn254_blackbox_solver`, tag `v1.0.0-beta.22`) stay **inline** in `outbe-zk-backend`, not in `[workspace.dependencies]`. `barretenberg-rs` is exact-pinned (`=5.0.0-nightly.20260522`). `outbe-poseidon` is a tagged git dep until published. Bump the noir tag, the bb pin, and the version in mise.toml together. `deny.toml` allows exactly two git origins: `noir-lang/noir` and `outbe/outbe-poseidon`.

## Profiles and test gotchas

- `[profile.dev]` is `opt-level = 3` deliberately — proving is unusably slow otherwise. Don't "fix" this.
- The proving roundtrips — `outbe-zk-backend`'s `tests/emit_mint.rs` and `tests/paynote.rs`, and `outbe-l2-demo`'s `tests/roundtrip.rs` and `benches/proving.rs` — build the barretenberg FFI and download/cache the SRS. The fast suites — `outbe-zk-core`, `outbe-zk-canonical`, `outbe-l2-claims`, `outbe-l2-zk-canonical` and the demo's `tests/witness.rs` / `tests/proof_system.rs` — read committed artifacts and need neither the toolchain nor the network.

## Style

- Standard `rustfmt` (no custom `rustfmt.toml`).
- `outbe-zk-canonical`'s `noir` registry is generated/frozen — never hand-edit `resources/circuits/` or the `build.rs` codegen output; mint via `cargo xtask freeze-circuits`.
- The `generated` modules in `outbe-l2-claims` and `outbe-l2-zk-canonical` are the same deal — edit `outbe-l2-claims/claims/<claim>/abi.json` or `outbe-l2-zk-canonical/l2/manifest.toml` and rebuild; mint root artifacts via `cargo xtask l2 admit`.
