# outbe-zk-circuit-noir

Noir circuit implementation for ZK proofs using the Barretenberg backend (UltraHonk).

## Noir Sub-projects

| Directory | Type | Nargo Name | Description |
|-----------|------|------------|-------------|
| `outbe-circuit-core/` | lib | `outbe_circuit_core` | Shared circuit library (ownership + inclusion modules) |
| `outbe-full-circuit/` | bin | `full_proof` | Full proof: ownership + Merkle inclusion |
| `outbe-ownership-circuit/` | bin | `ownership_proof` | Ownership-only proof |

## Compiled Bytecodes

Pre-compiled circuit bytecodes are stored in `data/`:
- `data/full_proof.json`
- `data/ownership_proof.json`

## Building Circuits

```bash
# Test all circuits
cd outbe-circuit-core && nargo test
cd outbe-full-circuit && nargo test
cd outbe-ownership-circuit && nargo test

# Compile binary circuits
cd outbe-full-circuit && nargo compile
cd outbe-ownership-circuit && nargo compile

# Copy bytecodes to data/
cp outbe-full-circuit/target/full_proof.json data/
cp outbe-ownership-circuit/target/ownership_proof.json data/
```

## Rust Wrapper

The Rust crate provides `NoirFullProofCircuit` and `NoirOwnershipCircuit`, both implementing `ZKCircuit` defined locally in `src/circuit_traits.rs`. They handle witness map construction, proof generation, and verification via the vendored `noir_rs` Barretenberg bindings under `src/barretenberg/` + `src/{circuit,execute,witness}.rs` (see `NOTICE.md` for upstream attribution).

## Mobile builds

The `[lib]` section in `Cargo.toml` declares `crate-type = ["staticlib", "cdylib", "rlib"]` so this crate compiles into the per-target artifacts the Swift / Kotlin consumers (`outbe-integration` UniFFI wrappers, Wallet SDK) load:

| Target                    | Artifact                          | Used by              |
|---------------------------|-----------------------------------|----------------------|
| `aarch64-apple-ios`       | `liboutbe_zk_circuit_noir.a`        | iOS device           |
| `aarch64-apple-ios-sim`   | `liboutbe_zk_circuit_noir.a`        | iOS Apple-Silicon simulator |
| `aarch64-linux-android`   | `liboutbe_zk_circuit_noir.so`       | Android arm64-v8a    |
| `x86_64-linux-android`    | `liboutbe_zk_circuit_noir.so`       | Android x86_64 emulator |

CI builds all four on every PR (`build-ios` + `build-android` jobs in `.github/workflows/ci.yml`). To reproduce locally:

### Prerequisites

- **All targets** — `rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android x86_64-linux-android` and `cargo install cargo-ndk --locked`.
- **iOS only** — Xcode CLI tools (`xcode-select --install`). No extra config needed; the SDK is auto-discovered.
- **Android only** — NDK r27+ (CI pins r27c; r29 works locally). The simplest install is `brew install --cask android-ndk` on macOS; the mise tasks below auto-discover the resulting path. For other install methods (Android Studio, manual unpack) set `ANDROID_NDK_HOME` explicitly to the directory containing `toolchains/llvm/prebuilt/`.

### Building (mise — recommended)

The repo ships a [`mise.toml`](../../mise.toml) with the same invocations CI uses. With [mise](https://mise.jdx.dev) installed:

```bash
mise run mobile:setup            # one-shot: rust targets + cargo-ndk
mise run build:ios               # both iOS slices
mise run build:android           # both Android slices
mise run build:mobile            # all four
# or any individual slice:
mise run build:ios-arm64
mise run build:ios-sim-arm64
mise run build:android-arm64-v8a
mise run build:android-x86_64
```

`mise tasks` lists everything.

### Building (raw cargo)

If you'd rather not adopt mise:

```bash
# iOS — output at target/<triple>/release/liboutbe_zk_circuit_noir.a
cargo build --release -p outbe-zk-circuit-noir --target aarch64-apple-ios
cargo build --release -p outbe-zk-circuit-noir --target aarch64-apple-ios-sim

# Android — driven via cargo-ndk so the API-level "magic prefix" clang
# wrappers (e.g. aarch64-linux-android24-clang) get picked up.
# Output at jniLibs/<abi>/liboutbe_zk_circuit_noir.so
export ANDROID_NDK_HOME=/opt/homebrew/Caskroom/android-ndk/*/AndroidNDK*.app/Contents/NDK
cargo ndk --target arm64-v8a --platform 24 --output-dir ./jniLibs build --release -p outbe-zk-circuit-noir
cargo ndk --target x86_64    --platform 24 --output-dir ./jniLibs build --release -p outbe-zk-circuit-noir
```

### Verifying the produced artifacts

Sanity-check that the toolchains actually stamped the expected target metadata (not the host platform):

```bash
# iOS — should report platform 2 (PLATFORM_IOS) for device, 7 (PLATFORM_IOSSIMULATOR) for sim
otool -l target/aarch64-apple-ios/release/liboutbe_zk_circuit_noir.a | grep -A2 LC_BUILD_VERSION
otool -l target/aarch64-apple-ios-sim/release/liboutbe_zk_circuit_noir.a | grep -A2 LC_BUILD_VERSION

# Android — should report `ARM aarch64` / `x86-64` ELFs linked against libc.so + libc++_shared.so
file jniLibs/arm64-v8a/liboutbe_zk_circuit_noir.so
file jniLibs/x86_64/liboutbe_zk_circuit_noir.so
```

For Android, the `.note.android.ident` section's first u32 is the **min SDK API level**:

```bash
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$(uname -s | tr A-Z a-z)-x86_64/bin/llvm-readelf" \
  --notes jniLibs/arm64-v8a/liboutbe_zk_circuit_noir.so | grep -A1 NT_ANDROID_TYPE_IDENT
# description data: 18 00 00 00 ... → 0x18 = API 24
```

## Proof Format

The `noir_rs` crate from zkpassport returns proofs with the following format:

```
[num_public_inputs (4 bytes BE)] [public_input_0: 32B] [public_input_1: 32B] ... [proof_bytes...]
```

The `split_proof()` function in `src/lib.rs` parses this format and splits the combined proof into separate public inputs and proof bytes for storage in the `NoirProof` struct.

## Testing

```bash
cargo test -p outbe-zk-circuit-noir
```

Note: Full integration tests (test_full_proof_round_trip, test_ownership_proof_round_trip) require circuit artifacts compiled with Nargo v1.0.0-beta.20 — `xtask` enforces this pin and refuses to compile circuits with any other version. Install via `noirup -v 1.0.0-beta.20`. See the project root CLAUDE.md for the circuit-change workflow.
