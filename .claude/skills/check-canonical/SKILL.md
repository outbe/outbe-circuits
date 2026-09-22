---
name: check-canonical
description: Check that the frozen canonical registry in outbe-zk-canonical is self-consistent, and optionally that no circuit has drifted from its .nr source. Use before committing/pushing or to triage a CI failure about canonical drift.
---

The canonical registry is frozen and committed; `crates/outbe-zk-canonical/build.rs` is read-only (it never runs nargo/bb). There are two levels of check.

## Level 1 — registry consistency (fast, no toolchain)

Run `cargo build -p outbe-zk-canonical`. `build.rs` reads `circuits/manifest.toml` + `resources/circuits/` and **panics** on any inconsistency (a missing `circuit.vk`, bytecode dropped without a preserved `circuit_hash`, malformed base64, a bad ABI, etc.).

- **Clean build** → the committed registry is internally consistent. Stop.
- **Build panic** → the manifest and the frozen artifacts disagree; report the panic message (it names the offending `<module>@<version>`).

## Level 2 — ACIR drift vs sources (slow, needs the Noir toolchain)

Only when `.nr` sources under `noir/` changed and you need to know whether a new frozen version is owed. Needs nargo + bb (`mise run install:zk-toolchain`). Run `cargo xtask freeze-circuits`:

- **`0 minted` / all `unchanged`** → the sources compile to the same ACIR as the frozen artifacts; nothing to do.
- **`minted ...`** → a circuit drifted; recommend `/freeze-circuits` to mint and commit the new version alongside the source change.

Note: `freeze-circuits` **writes** to `manifest.toml` / `resources/` when it mints. For a purely read-only check prefer Level 1; reach for Level 2 only when you actually intend to freeze.
