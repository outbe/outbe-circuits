---
name: check-canonical
description: Check that the frozen canonical registry in outbe-zk-canonical is self-consistent, and optionally that no circuit has drifted from its .nr source. Use before committing/pushing or to triage a CI failure about canonical drift.
---

The canonical registry is frozen and committed; `crates/outbe-zk-canonical/build.rs` is read-only (it never runs nargo/bb). There are two levels of check.

## Level 1 — registry consistency (fast, no toolchain)

Run `cargo build -p outbe-zk-canonical`. `build.rs` reads L1 releases at conventional `resources/circuits/<module>/<version>/` paths and L2 flat packages under `l2/<chain_id>/<path>/`. It fails on missing/malformed artifacts, conflicting registrations, or a committed L2 VK that disagrees with its manifest `vk_hash`.

- **Clean build** → the committed registry is internally consistent. Stop.
- **Build panic** → the manifest and the frozen artifacts disagree; report the panic message (it names the offending `<module>@<version>`).

## Level 2 — source and VK reproducibility (needs the pinned Noir toolchain)

Use when sources, frozen artifacts, or toolchain pins changed, or to reproduce the CI circuit check. Install the pins with `mise install nargo bb`, then run `cargo xtask freeze-circuits --check` (or `mise run freeze-circuits:check`).

- **`all active circuits reproduce.`** → active L1 ACIR/ABI/VKs reproduce, and all registered L2 packages' committed and freshly derived VKs match their pins.
- **Nonzero exit** → report the named failure. L1 changes use versioned freezing; stable L2 key changes need a new package and explicit chain version. Mutable L2 pins can be refreshed without a chain-version bump.

The check asserts exact tool versions and uses a scratch tree cleaned on success/failure. It never modifies committed files. L2 stability is verification-identity-only: source spelling and ABI-only changes pass if the derived VK is unchanged. L1 still compares complete ACIR/ABI/VK. Do not combine `--check` with `--abi-change` or `--semantic`.
