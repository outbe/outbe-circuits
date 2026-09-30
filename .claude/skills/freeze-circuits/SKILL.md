---
name: freeze-circuits
description: Freeze catalog-declared Noir sources: mint L1 circuit releases or refresh flat L2 packages under their stable/mutable VK policy, then check reproduction and report the source/artifact/manifest changes together.
---

Use when sources under canonical `noir/` or `l2/` changed and the user wants to update committed artifacts. L1 has immutable releases; L2 has explicit chain versions selecting package arrays.

Prereq: the pinned Noir toolchain must be installed — `mise install nargo bb` (nargo 1.0.0-beta.22 + bb 5.0.0-nightly.20260522). The xtask locates them via `$NARGO`/`$BB`, then `~/.nargo/bin/nargo` and `~/.bb/bb`, then PATH.

For verification only, use `cargo xtask freeze-circuits --check`. It checks exact tool pins, reproduces complete L1 ACIR/ABI/VKs and L2 pinned VKs in scratch space, and never modifies committed files. L2 field renames/comments do not fail when verification identity stays unchanged.

## Steps

1. **Confirm what changed.** Run `git status` and confirm at least one catalog-declared source package under `noir/` or `l2/` is modified. For a directory-only move with unchanged constraints, use the read-only reproduction check instead of minting a release.

2. **Freeze.** Run `cargo xtask freeze-circuits`.
   - **L1:** unchanged ACIR/ABI is skipped; changed ACIR mints a patch release; changed ABI requires `--abi-change` or `--semantic`. Superseded releases retain their VK/hash.
   - **L2 stable:** the derived VK must equal the pinned `vk_hash`; unchanged-key ABI/bytecode refresh is allowed. A different key requires a new package path and explicitly declared chain version.
   - **L2 mutable:** refresh flat artifacts and pins in place. Demo stays on chain version `1.0.0`. No chain version ever auto-bumps; any stable reference protects a shared package.
   - **New L2 package:** create source/Nargo files without frozen artifacts, declare its path, and optionally omit `vk_hash`; first freeze fills the pin. Removing an existing frozen stable package's pin cannot bypass key protection.
   - **Verify:** run `cargo xtask freeze-circuits --check` afterward.

3. **Show what to commit.** List source changes, the modified catalog, new L1 releases under `resources/circuits/<module>/<version>/`, and refreshed L2 `abi.json`, `bytecode.b64`, and `circuit.vk` directly in their package directories. Commit them together.

4. **Do not commit** unless asked. Report L1 versions minted and L2 packages refreshed separately; a successful L2 refresh can correctly report zero minted circuit versions.

## Don'ts

- Do not hand-edit frozen artifact bytes or identity pins. Use xtask; stable L2 pins identify verification keys, not source or ABI spelling.
- Do not run individual `nargo compile` / `bb write_vk` commands — go through xtask.
- A `0 minted` result on a source edit is normal: the noir optimizer can collapse an edit to the same ACIR, in which case identity is unchanged and no new version is owed.
