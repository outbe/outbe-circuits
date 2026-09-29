---
name: check-canonical
description: Check that the frozen canonical registry in outbe-zk-canonical is self-consistent, and optionally that no circuit has drifted from its .nr source. Use before committing/pushing or to triage a CI failure about canonical drift.
---

The canonical registry is frozen and committed; `crates/outbe-zk-canonical/build.rs` is read-only (it never runs nargo/bb). There are two levels of check.

## Level 1 — registry consistency (fast, no toolchain)

Run `cargo build -p outbe-zk-canonical`. `build.rs` reads `circuits/manifest.toml` + `resources/circuits/` and **panics** on any inconsistency (a missing `circuit.vk`, bytecode dropped without a preserved `circuit_hash`, malformed base64, a bad ABI, etc.).

- **Clean build** → the committed registry is internally consistent. Stop.
- **Build panic** → the manifest and the frozen artifacts disagree; report the panic message (it names the offending `<module>@<version>`).

## Level 2 — source and VK reproducibility (needs the pinned Noir toolchain)

Use when sources, frozen artifacts, or toolchain pins changed, or to reproduce the CI circuit check. Install the pins with `mise install nargo bb`, then run `cargo xtask freeze-circuits --check` (or `mise run freeze-circuits:check`).

- **`all active circuits reproduce.`** → all five active circuits' decoded bytecode, structural ABI, and freshly derived VK match the committed artifacts.
- **Nonzero exit** → report the failing circuit and artifact or toolchain diagnostic. If a source change was intentional, use `/freeze-circuits` to mint and commit its new version.

The check asserts the exact `mise.toml` nargo/bb versions and compiles a per-process scratch copy under `target/`, cleaned on success or failure. It never mints versions, reconciles retired artifacts, or modifies the manifest, frozen artifacts, or tracked Noir compiler output. A normal freeze can skip unchanged ACIR/ABI without checking the VK; `--check` always re-derives it. Do not combine `--check` with `--abi-change` or `--semantic`.
