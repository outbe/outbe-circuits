---
name: freeze-circuits
description: Run the circuit-freeze workflow when Noir sources under crates/outbe-zk-canonical/noir/ have changed. Runs `cargo xtask freeze-circuits` (the only step that runs nargo/bb), which mints a new frozen version for any circuit whose ACIR changed, updates the manifest + resources, then surfaces the dirty files to commit together with the source change.
---

Use this skill when `.nr` sources under `crates/outbe-zk-canonical/noir/` have been edited and the user wants to mint the new frozen circuit version(s) before committing.

Prereq: the pinned Noir toolchain must be installed — `mise run install:zk-toolchain` (nargo 1.0.0-beta.22 + bb 5.0.0-nightly.20260522). The xtask locates them via `$NARGO`/`$BB` or `~/.nargo/bin/nargo` and `~/.bb/bb`.

## Steps

1. **Confirm what changed.** Run `git status` and confirm at least one file under `crates/outbe-zk-canonical/noir/` is modified. If nothing under `noir/` changed, this skill is the wrong tool — ask the user what they actually want.

2. **Freeze.** Run `cargo xtask freeze-circuits`. For each of the 11 circuits it prints either `unchanged <module> @ <ver>` (ACIR identical → no-op) or `minted <module> X -> Y (old -> deprecated)` (ACIR changed → new frozen version; the superseded one is set `deprecated`, keeping only its VK). The first barretenberg build is multi-minute — do not kill it.
   - **ABI changed?** The freeze requires explicit intent for a public-input-layout change: pass `--abi-change` (minor bump) or `--semantic` (major bump + a new `DOMAIN` decision).

3. **Show what to commit.** Run `git status` and list the modified `crates/outbe-zk-canonical/circuits/manifest.toml` plus the new `resources/circuits/<module>/<version>/` artifacts. These MUST be committed together with the `.nr` source change — the PR review is the audit gate for admitting a circuit.

4. **Do not commit** on the user's behalf unless they ask. End with a one-line summary of what was minted (or "0 minted — ACIR unchanged").

## Don'ts

- Do not hand-edit `circuits/manifest.toml` artifact hashes or anything under `resources/circuits/` — they're frozen, derived from nargo/bb output.
- Do not run individual `nargo compile` / `bb write_vk` commands — go through xtask.
- A `0 minted` result on a source edit is normal: the noir optimizer can collapse an edit to the same ACIR, in which case identity is unchanged and no new version is owed.
