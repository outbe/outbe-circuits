## Third-party code attribution

This crate includes code derived from
[zkpassport/noir_rs](https://github.com/zkpassport/noir_rs) (Apache-2.0).
The vendored files live directly under `src/` (the `barretenberg/`,
`circuit.rs`, `execute.rs`, and `witness.rs` modules); each carries
an SPDX `Apache-2.0` header and a "Vendored from zkpassport/noir_rs"
attribution comment so the third-party signal is preserved without a
nested `vendor/` directory.

See `vendor/noir_rs/LICENSE` for the original license terms.

The vendored code is byte-identical to the upstream source at
`v1.0.0-beta.20` (commit `d2bb6e5`); the surrounding noir-lang crate
deps are pinned to `v1.0.0-beta.22`, which the vendored glue still
compiles against unmodified. The only project-local override is the
`barretenberg-rs` version pin (`=5.0.0-nightly.20260522`), which is
declared in this crate's `Cargo.toml` rather than carried as a source
modification.
