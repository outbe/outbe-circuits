# outbe-zk-core-derive

[![CI](https://github.com/outbe/outbe-circuits/actions/workflows/ci.yml/badge.svg)](https://github.com/outbe/outbe-circuits/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

`#[derive(Entity)]` for [`outbe-zk-core`](../outbe-zk-core) — give a typed NFT
struct its `Entity` impl from per-field `#[outbe(...)]`
roles, so the canonical hash preimage is read off the struct definition instead
of a hand-built `Vec<Field>`. It carries the workspace version, the same one
`outbe-zk-core` carries.

## Architecture

The macro emits, concrete over `ark_bn254::Fr`:

- `impl Entity` — `id()` and `encode_body()`. The protocol's default
  `entity_hash()` folds them: `hash = H(id, body…)`.

Field types must implement the encoding seam. A scalar folds to exactly one
element via `FieldElement` by default; `#[outbe(limbed)]` routes it through
`FieldEncode` instead, yielding the several elements its type needs — a
`uint256`, for instance, uses the canonical three-limb `[120, 120, 16]`-bit
representation. A `Vec<T>` field always folds through `FieldEncode` as a
canonical **set** — `[ len, e₀, e₁, … ]` with the elements strictly ascending by
field value. The caller supplies it already sorted and de-duplicated; anything
else is rejected at hash time with `Error::UnsortedSet`. The length prefix is
what keeps two adjacent set-valued fields from flattening ambiguously. The
`alloy` feature on `outbe-zk-core` provides these impls for `Address` / `U256` /
`B256`.

### Field roles

Every field must carry one of the roles `id`, `body` or `skip` — a consensus
preimage must never silently omit a field. A field with no `#[outbe(...)]`
attribute, or one that names only `pos` / `limbed`, is a compile error.

| Role | Meaning |
| ---- | ------- |
| `#[outbe(id)]` | Exactly one field; it *is* the entity id, and the seed the body folds onto. Must be a single element. |
| `#[outbe(body)]` | The entity body, folded from the id. |
| `#[outbe(skip)]` | Explicitly excluded from the hash preimage. |
| `#[outbe(limbed)]` | Folds a *scalar* through `FieldEncode` (several elements) instead of `FieldElement` (one). Intent only — the limb count is a property of the type. Rejected on a `Vec<T>`. |
| `#[outbe(pos = N)]` | Explicit fold position within the `body` group. All-or-nothing; positions must be unique. Lets a struct mirroring a `sol!` layout fold in the protocol's canonical order regardless of declaration order. |

The struct must have named fields and no generic parameters.

## Usage

```toml
[dependencies]
outbe-zk-core = { version = "0.11", features = ["alloy"] }
outbe-zk-core-derive = "0.11"
alloy-primitives = "1"
```

The real user of this macro is `TributeDraftClaim` in
[`outbe-l2-claims`](../outbe-l2-claims/src/claims/tribute.rs); this
is a smaller struct that exercises every role.

```rust
use outbe_zk_core::entity::Entity;
use outbe_zk_core_derive::Entity;
use alloy_primitives::{Address, B256, U256};   // impls come from the `alloy` feature above

#[derive(Entity)]
struct DemoClaim {
    #[outbe(id)]                    id: B256,          // must be < FR_MODULUS
    #[outbe(body, pos = 0)]         owner: B256,
    #[outbe(body, pos = 1)]         issuer: Address,
    #[outbe(body, limbed, pos = 2)] amount: U256,      // three canonical limbs
    #[outbe(body, pos = 3)]         su_ids: Vec<B256>, // canonical set: sorted, de-duplicated
    #[outbe(skip)]                  cached_hash: B256, // not in the preimage
}

let claim = DemoClaim { /* … */ };
let hash = claim.entity_hash()?;
```

Declaration order is the fold order when no field sets `pos`; otherwise the
body is sorted by `pos`. A field with no role is a compile error (use
`#[outbe(skip)]` to exclude it intentionally).

## License

[MIT](../../LICENSE) — same as `outbe-zk-core`.
