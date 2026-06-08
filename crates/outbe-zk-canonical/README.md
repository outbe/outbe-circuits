# `outbe-zk-canonical`

Authoritative source-of-truth for Outbe L2 canonical Noir circuit
descriptors. Pure static data; **no FFI, `no_std`-compatible**.

Consumers:
- `outbe-chain` — wraps each `CircuitDescriptor` with chain-policy
  timing (`activated_at_block` / `deprecated_at_block`) and uses
  this to gate proof acceptance in the `zk_verify` precompile.
- Solidity test fixtures / audit tooling — can link this to get
  the canonical VK bytes and circuit hashes without any FFI.

## Versioning model

**Append-only.** Existing descriptors are never modified — that
would break consensus on what bytes are canonical. New circuit
revisions (different source code ⇒ different ACIR ⇒ different
`circuit_hash`) get appended as new descriptors.

Crate version bumps follow:
- **Patch** (0.1.x → 0.1.y) for bug fixes, label/version-string
  tweaks, doc changes — no descriptor changes
- **Minor** (0.x.y → 0.(x+1).0) for appended descriptors
- **Major** (x.y.z → (x+1).0.0) is reserved for breaking changes
  to `CircuitDescriptor` shape (would require coordinated
  `outbe-chain` migration)

## Regenerate

After modifying a circuit under `crates/outbe-zk-circuit-noir/`:

```bash
cargo run --package xtask -- regenerate-canonical
```

That command:
1. Runs `nargo compile` on every entry in `xtask::CIRCUITS`
2. Reads the compiled `<name>.json` artifact (base64 ACIR)
3. Computes `circuit_hash = keccak256(base64_decode(acir))`
4. Calls `noir_rs::barretenberg::verify::get_ultra_honk_keccak_verification_key`
   to derive the UltraHonkKeccak VK
5. Writes `vk_bytes` to `res/vks/<circuit_label>.vk`
6. Computes `vk_hash = keccak256(vk_bytes)`
7. Regenerates `src/lib.rs` const declarations + appends to
   `ALL_CIRCUITS`

### CI gate

```bash
cargo run --package xtask -- regenerate-canonical --check
```

Fails if regeneration would produce a diff vs committed state.
Catches:
- Circuit source changed without regenerating
- Manually-edited `.vk` files or hash constants
- SRS drift

## Consuming from `outbe-chain`

```toml
# outbe-chain/Cargo.toml
[dependencies]
outbe-zk-canonical = "0.2"
```

```rust
// outbe-chain/src/zk/circuits.rs
use outbe_zk_canonical::{CircuitDescriptor, SU_OWNERSHIP, TD_OWNERSHIP};

pub struct CanonicalCircuit {
    pub descriptor: &'static CircuitDescriptor,
    pub activated_at_block:  u64,
    pub deprecated_at_block: Option<u64>,
}

pub const CANONICAL_CIRCUITS: &[CanonicalCircuit] = &[
    CanonicalCircuit {
        descriptor:          &SU_OWNERSHIP,
        activated_at_block:  0,
        deprecated_at_block: None,
    },
    // ...
];
```

## Design

See the internal `outbe-chain` design docs for the full spec
(rolling-upgrade procedure, emergency response, precompile ABIs,
etc.).
