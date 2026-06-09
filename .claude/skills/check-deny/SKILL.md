---
name: check-deny
description: Run `cargo deny check all` locally to mirror the CI cargo-deny job. Use before committing, before pushing, after editing `Cargo.toml` / `Cargo.lock` / `deny.toml`, or to triage a CI failure complaining about license / advisory / duplicate-version / git-source policy.
---

Run `cargo deny check all` from the workspace root. This is the exact command the `cargo-deny` job in `.github/workflows/ci.yml` runs.

- **Exit 0 / `advisories ok, bans ok, licenses ok, sources ok`**: policy is satisfied. Tell the user "cargo-deny clean" and stop.
- **Any errors**: identify which check failed (`advisories`, `bans`, `licenses`, `sources`) and propose the upstream-preferred fix from `deny.toml`'s header comment:
  - `multiple-versions` → prefer bumping the dep that pulls in the older copy, or add a `[patch.crates-io]`. Only add to `[bans.skip]` if upstream-blocked, with the transitive chain written into a comment.
  - `advisory` → upgrade the affected crate. Only add to `[advisories.ignore]` with the `RUSTSEC-*` id and a written reason.
  - `licenses` → if a new SPDX expression is legitimate, extend `[licenses.allow]` with a comment naming the crate. Don't blanket-allow.
  - `sources` → if a new git origin is intentional, extend `[sources.allow-git]` with a comment.
- **Warnings**: warnings (`unmatched license allowance`, `unnecessary skip`, `advisory was not encountered`) mean `deny.toml` is now out of sync with the actual graph. Surface them and recommend removing the stale entries — leaving them rots the policy.

Do not modify `deny.toml` or any other file in this skill unless the user explicitly asks to apply the fix. Read-only by default; report findings.

## Don'ts

- Do not silence a real violation by skipping or ignoring without a written rationale — that defeats the policy.
- Do not edit the vendored `crates/outbe-zk-circuit-noir/src/vendor/noir_rs/` to dodge a transitive warning.
- Do not run individual checks (`cargo deny check bans` etc.) instead of `check all` — CI runs `check all`; mismatched scopes hide regressions.
