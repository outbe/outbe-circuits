# outbe-zk-canonical

[![crates.io](https://img.shields.io/crates/v/outbe-zk-canonical.svg)](https://crates.io/crates/outbe-zk-canonical)
[![release](https://img.shields.io/github/v/release/outbe/outbe-circuits.svg)](https://github.com/outbe/outbe-circuits/releases)
[![CI](https://github.com/outbe/outbe-circuits/actions/workflows/ci.yml/badge.svg)](https://github.com/outbe/outbe-circuits/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Concrete canonical circuit + witness types for the Outbe protocol (ownership, the
flat-aggregation tiers n1–n64, full proof), built on the generic seams in
`outbe-protocol` (`Circuit` / `CircuitId` / `CircuitSuite`). It is also the **in-code,
versioned circuit registry**: the authoritative, append-only record of every
released circuit version and its on-chain identity.

## What the build produces

`cargo build` runs `build.rs`, which is **read-only** — it does **not** run
`nargo`/`bb`. It reads the committed frozen artifacts and emits, into
`outbe_zk_canonical::noir`:

- `pub mod <module> { … }` for the **latest active** version of each circuit —
  `Witness` / `PublicInputs` types, the `Circuit<S>` + `CircuitId` impls on a
  marker, and identity consts (`LABEL`, `VERSION`, `CIRCUIT_HASH`, `BYTECODE_B64`,
  `VK_BYTES`, `VK_HASH`). This is the prover-facing API.
- `pub const CIRCUIT_REGISTRY: &[RegistryEntry]` over **every** version (the
  verification view — VK + hashes, no bytecode). A verifier dispatches on this:
  match a submission's `circuit_id` (`vk_hash` / `label@version`), check `status`,
  verify against `vk_bytes`. Old + new versions coexist here, so a chain can accept
  both during a rollout.

So: **registry = all versions; codegen = latest active**.

## Layout

```
circuits/manifest.toml                       # append-only registry index
resources/circuits/<module>/<version>/       # frozen, immutable artifacts
    bytecode.b64   # ACIR — proving artifact (active only)
    abi.json       # drives the Rust witness types (active only)
    circuit.vk     # UltraHonkKeccak VK — verification (kept while not revoked)
noir/                                        # the .nr sources = the "head" (next version)
```

`manifest.toml` is the source of truth: a global `proof_system` (the bb pin) plus
one `[[circuit]]` per `(module, version)` with `label`, `status`, and — once the
bytecode is dropped — the preserved `circuit_hash`.

## Lifecycle & storage policy

| status | accepts proofs? | bytecode + abi | vk | in `CIRCUIT_REGISTRY`? |
|---|---|---|---|---|
| `active` | yes | kept (provable) | kept | yes (+ head `pub mod`) |
| `deprecated` | verifies in-flight only | **dropped** | kept | yes (VK-only) |
| `revoked` | no | dropped | **dropped** | **no** (manifest keeps the record) |

Rationale: bytecode is a *proving* artifact (a retired prover ships its own);
verification needs only the VK. So a superseded version keeps its VK to keep
verifying in-flight proofs, and a fully-obsolete one drops everything. The
chain-side versioning/rollout design is in
[`../docs/circuit-versioning.md`](../docs/circuit-versioning.md).

## Evolving a circuit

Editing the `.nr` sources does **not** change anything by itself — released
versions are frozen. Minting a new version is a deliberate step:

```sh
cargo xtask freeze-circuits          # the only step that runs nargo/bb
```

For each circuit whose ACIR changed it mints a new frozen version:

- **unchanged ACIR** → skipped (the freeze detects true ACIR equivalence — even a
  source edit that the noir optimizer removes is a no-op here).
- **changed ACIR, same ABI** → patch bump (e.g. `1.0.0 → 1.0.1`).
- **ABI changed** → pass `--abi-change` (minor) or `--semantic` (major + a new
  `DOMAIN` decision) to make the public-input-layout change explicit.

On a supersede it sets the previous version `deprecated`, then a reconcile pass
enforces the storage policy above (preserving `circuit_hash` before any deletion).
The new artifacts + manifest land in a **PR** — that review is the audit gate for
admitting a circuit. Status transitions (active → deprecated → revoked) are edits
to `manifest.toml`; the next `freeze-circuits` reconciles the on-disk artifacts.

Example — bumping the n2 tier:

```
$ cargo xtask freeze-circuits
  unchanged  flat_aggregation_n1 @ 1.0.0
  minted     flat_aggregation_n2 1.0.0 -> 1.0.1  (old -> deprecated)
  ...
# manifest: n2 v1.0.0 deprecated (+circuit_hash), v1.0.1 active
# resources: n2/1.0.0/ -> circuit.vk only;  n2/1.0.1/ -> bytecode+abi+vk
# CIRCUIT_REGISTRY: both n2 entries;  pub mod flat_aggregation_n2 -> v1.0.1
```

## Publishability

This crate stays acir-free (no git/noir deps) and ships to crates.io — `nargo`/`bb`
are invoked only by the `xtask` at freeze time, never on a normal build. The
committed frozen artifacts make `cargo build` deterministic with or without the
noir toolchain installed.
