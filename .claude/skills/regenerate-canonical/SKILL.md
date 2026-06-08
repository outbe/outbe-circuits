---
name: regenerate-canonical
description: Run the canonical circuit-change workflow when Noir circuits have changed. Recompiles bytecodes via `cargo xtask compile-circuits`, regenerates the canonical VKs and circuit hashes via `cargo xtask regenerate-canonical`, then surfaces the dirty files so they get committed together with the circuit source change.
---

Use this skill when Noir circuit sources under `crates/outbe-zk-circuit-noir/circuits/` have been edited and the user wants to refresh derived artifacts before committing.

## Steps

1. **Confirm what changed.** Run `git status` and confirm at least one file under `crates/outbe-zk-circuit-noir/circuits/` is modified. If nothing under `circuits/` has changed, this skill is the wrong tool — ask the user what they actually want.

2. **Compile circuits.** Run `cargo xtask compile-circuits`. This rewrites bytecodes in `data/`. The first invocation may trigger a multi-minute barretenberg-rs C++ FFI build — do not kill it.

3. **Regenerate canonical descriptors.** Run `cargo xtask regenerate-canonical`. This rewrites files in `crates/outbe-zk-canonical/` with new UltraHonkKeccak VKs and circuit hashes.

4. **Show the user what to commit.** Run `git status` and list the changed paths under `data/` and `crates/outbe-zk-canonical/`. Remind the user these MUST be committed in the same commit as the circuit source change — drift between the three is the bug class this workflow exists to prevent.

5. **Do not commit on the user's behalf** unless they ask. End with a one-line summary of what's now dirty.

## Don'ts

- Do not hand-edit anything in `crates/outbe-zk-canonical/` — it's generated.
- Do not run individual `nargo compile` commands — go through xtask.
- Do not modify `crates/outbe-zk-circuit-noir/src/vendor/noir_rs/`.
