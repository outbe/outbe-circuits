# outbe-circuits

**Noir circuits and the Rust FFI prover wrapper** for the outbe
zero-knowledge proof system.

### Noir sub-projects

Three sibling Nargo packages (each with its own `Nargo.toml`) under
`crates/outbe-zk-circuit-noir/`:

| Directory                  | Nargo name            | Type | Role                                                                              |
|----------------------------|-----------------------|------|-----------------------------------------------------------------------------------|
| `outbe-circuit-core/`      | `outbe_circuit_core`  | lib  | Shared `ownership` + `inclusion` modules. Depends on `noir-lang/poseidon` v0.3.0 and `noir-lang/schnorr` v0.2.0. |
| `outbe-ownership-circuit/` | `ownership_proof`     | bin  | Single-NFT ownership proof. Public inputs: `[owner, nft_hash]`.                   |
| `outbe-full-circuit/`      | `full_proof`          | bin  | Ownership + depth-8 Merkle inclusion. Public inputs: `[owner, nft_hash, expected_merkle_root]`. |

Both bin crates pull the ownership/inclusion logic from
`outbe_circuit_core` via a relative path dep — there is **one**
ownership implementation shared across both circuits, so editing the
lib forces a recompile of both bins and a regen of `outbe-zk-canonical`.

## Noir toolchain

`nargo` is pinned to **1.0.0-beta.20**. Install via:

```bash
noirup -v 1.0.0-beta.20
```

`xtask` refuses to compile under any other version because the
canonical VKs in `outbe-zk-canonical` are tied to that compiler's
output.

## Build

`cargo xtask` is aliased in `.cargo/config.toml`. Use these, not raw
`cargo build` / `nargo compile`, for anything circuit-related:

```bash
cargo xtask compile-circuits          # Compile all Noir circuits, write bytecodes to data/
cargo xtask regenerate-canonical      # Derive UltraHonkKeccak VKs + circuit hashes
cargo xtask regenerate-canonical --check  # Verify canonical data is in sync (no writes)
```

Standard `cargo` works for everything else:

```bash
cargo build --workspace
cargo test  --workspace --tests --no-run     # compile tests
cargo test  -p outbe-zk-canonical            # fast: pure-data tests
```

Full round-trip prove/verify tests under barretenberg take tens of
seconds. The `aggregation-full-tiers` feature on
`outbe-zk-circuit-noir` gates the expensive tier prove+verify tests;
off by default (each tier takes tens of seconds; N=64 several minutes).

### Profiles

`[profile.dev]` is set to `opt-level = 3` deliberately — proving is
unusably slow otherwise. Don't "fix" this.

## Circuit-change workflow

When a Noir circuit source changes, the commit must contain all three
artifacts together:

1. `cargo xtask compile-circuits` — regenerate `data/` bytecodes.
2. `cargo xtask regenerate-canonical` — regenerate VKs + circuit hashes
   in `outbe-zk-canonical`.
3. Commit the modified Noir source, the updated `data/` bytecodes, and
   the modified `crates/outbe-zk-canonical/` files in the **same**
   commit.

The `--check` variant catches drift; run it before pushing if unsure.

## Regenerating canonical descriptors

`cargo xtask regenerate-canonical` recompiles each circuit, derives
the canonical UltraHonkKeccak VK via the same `noir_rs` FFI the prover
uses, and emits the descriptors that `outbe-zk-canonical` ships. The
on-chain `zk_verify` precompile and every wallet prover will agree on
VK bytes by construction.

## Vendored noir_rs — read-only

`crates/outbe-zk-circuit-noir/src/vendor/noir_rs/` is vendored upstream
proving glue. **Do not modify these files.** Diverging breaks FFI
proof compatibility with the canonical VKs. If you think a change is
needed there, escalate — don't edit.

The pinned `acvm` / `acvm_blackbox_solver` / `bn254_blackbox_solver` /
`nargo` / `barretenberg-rs` deps exist specifically to satisfy this
vendored code. Bump them together when chasing a new noir release, not
individually.

## Mobile-loadable shapes

`outbe-zk-circuit-noir`'s `crate-type = ["staticlib", "cdylib", "rlib"]`
produces a `.a` consumable from iOS xcframeworks and a `.so`
consumable from Android's NDK loader alongside the regular `rlib` used
by other workspace crates. Driving the cross-compiles themselves
(cargo-ndk for Android, the iOS target triples, NDK toolchain
wrappers) is the consumer's responsibility — this repo only ships the
crate.

## License

Apache-2.0. The vendored `noir_rs` glue retains its upstream
Apache-2.0 license; see
`crates/outbe-zk-circuit-noir/NOTICE.md`.
