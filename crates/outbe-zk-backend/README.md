# outbe-zk-backend

The Noir **proving backend** for the canonical Outbe circuits: a shared ACVM
witness-solving core plus a barretenberg (UltraHonkKeccak, FFI) prover/verifier.

> **Not published to crates.io** (`publish = false`). It depends on the noir
> toolchain (`acir` / `acvm` / `bn254_blackbox_solver`) via git tags that
> crates.io cannot resolve, and links a native C++ barretenberg via FFI. Consume
> it as a git / workspace dependency.

## A circuit-generic prover/verifier

The proving core is **generic over any circuit** — it depends only on the
`outbe-zk-core` seams (`Circuit` with its prove-side `witness_inputs` /
verify-side `public_inputs`, and `CircuitId`), **not** on the
concrete `outbe-zk-canonical` (only the tests pull that in). A single
[`Barretenberg`] value implements both core seams for every `C: Circuit`:

- `ProofGenerator<C>` — `generate(&witness, &public) -> Result<Self::Proof, Error>`
- `ProofVerifier<C>` — `verify(&public, &proof) -> Result<bool, Error>`

So the same backend proves/verifies Emit mint, Paynote, a registered L2 claim
root (see [`examples/outbe-l2-demo`](../../examples/outbe-l2-demo)),
**or any circuit you define** that implements
the seams — you pick the circuit type at the call site via the `C` type parameter.

Generic verifier-wire validation lives in `outbe_zk_core::zkproof`.
The matching `emit_mint` and `paynote` modules in
`outbe-zk-canonical` own each circuit's strict layout and public-input decoder.

```rust
use outbe_zk_core::zk::{ProofGenerator, ProofVerifier};
use outbe_zk_backend::barretenberg::Barretenberg;
use outbe_zk_canonical::noir::paynote::Paynote;

// `witness` + `public` are the circuit's generated `Witness` / `PublicInputs`.
let bb = Barretenberg::default();            // zero-knowledge ON (see below)

// The circuit is chosen by the `C` type parameter — here `Paynote`.
let proof = ProofGenerator::<Paynote>::generate(&bb, &witness, &public)?;
let ok    = ProofVerifier::<Paynote>::verify(&bb, &public, &proof)?;
assert!(ok);
```

`Barretenberg::default()` keeps **zero-knowledge on** (`disable_zk = false`) — the
Paynote witness carries a spend key, so the proof must not leak it. Opt
into the faster `disable_zk = true` path only for public-input-only statements:

```rust
let bb = Barretenberg { disable_zk: true, ..Default::default() };
```

`preinit_srs(num_points)` warms the structured reference string up front (e.g.
before a batch of proofs) so the first `generate` doesn't pay the download/load.

## The native barretenberg library

This crate is the Rust side only: an ACVM witness solver plus the FFI calls
into barretenberg. The native library comes from the `barretenberg-rs`
dependency pinned in the workspace `Cargo.toml`, and resolving it is that
dependency's own business.

## SRS

The prover/verifier needs the Aztec CRS (structured reference string). The
backend uses a local cache and falls back to downloading the CRS, **verifying the
G1 prefix against a pinned SHA-256** before trusting it. Pinned sizes live in
`barretenberg::srs`; an unpinned size logs a warning to stderr.

## Building & testing

```bash
cargo build -p outbe-zk-backend
cargo test  -p outbe-zk-backend     # emit_mint + paynote prove/verify round-trips
cargo bench -p outbe-l2-demo        # proving cost, over the registered L2 tribute root
```

## License

[MIT](../../LICENSE)
