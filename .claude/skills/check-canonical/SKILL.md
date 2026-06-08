---
name: check-canonical
description: Check whether the canonical VK + circuit-hash data in `outbe-zk-canonical` is in sync with the current Noir circuit sources. Runs `cargo xtask regenerate-canonical --check` without writing anything. Use before committing, before pushing, or to triage a CI failure complaining about canonical drift.
---

Run `cargo xtask regenerate-canonical --check`.

- **Exit 0 / no diff reported**: canonical data matches the circuits. Tell the user "canonical is in sync" and stop.
- **Non-zero exit / drift reported**: tell the user which descriptors would change and recommend running `/regenerate-canonical` (or `cargo xtask regenerate-canonical`) to write the updates, then committing both `data/` and `crates/outbe-zk-canonical/` alongside the circuit-source change.

Do not write any files yourself in this skill — it's read-only by design.
