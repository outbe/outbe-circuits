# outbe-l2-claims

The L1-to-L2 claim contract, and nothing else.

Outbe L1 admits NFTs from L2 networks by proof. A **claim** is what such an NFT
is: the entity whose hash is `nft_hash`, the binding formula whose result is
`binding_hash`, and the fixed list of public inputs a proof of that claim
exposes. This crate is those three things. It holds no verification key, no
committed circuit root and no registry — those are
[`outbe-l2-zk-canonical`](../outbe-l2-zk-canonical), which depends on this
crate.

## Why it is its own crate

The dependency runs one way: registry → claims. So a consumer that only folds
claims — a prover, or a TEE image whose identity is a measurement over its own
bytes — depends on this crate, and **no verification key can reach its binary
under any cargo invocation.** Registering an L2 does not move a byte it
compiles.

That guarantee used to be a default-on `l2-keys` cargo feature on a single
crate, and a feature cannot carry it: cargo unifies features across the
selected package set, so selecting a `--bin` from the workspace root, a bare
workspace build, or a stale artifact at a shared target path each turned the
keys back on. A package boundary has no such hole.

This crate also has no dependency on `outbe-zk-canonical` (the L1 circuits) or
on `outbe-zk-backend`, in either direction: a claim consumer takes it without
taking barretenberg. It re-exports `outbe_zk_core`, so one dependency reaches
`codec`, `hash`, `keys`, `Entity` and `Error` as well.

## What a claim is

Three things, all under `claims::<name>`:

| Part | Where | Becomes |
|------|-------|---------|
| The entity | `src/claims/<name>.rs`, `#[derive(Entity)]` | `nft_hash` |
| The binding formula | `src/claims/<name>.rs` | `binding_hash` |
| The public-input ABI | `claims/<name>/abi.json` | the generated `PublicInputs` |

## The tribute claim

### The entity

`TributeDraftClaim` in `src/claims/tribute.rs` is the one definition of what a
tribute draft hashes to. Seven hashed members — the `id` and six body
members — and `pos`, not declaration order, pins the fold:

| Role | Field | Type | Meaning |
|------|-------|------|---------|
| `id` | `id` | `B256` | the L2's draft id; the seed the body folds onto |
| `body, pos = 0` | `owner` | `B256` | the L2's owner commitment, an opaque field element |
| `body, pos = 1` | `worldwide_day` | `u64` | the day the tribute is offered for |
| `body, pos = 2` | `currency` | `u16` | ISO-4217 numeric code |
| `body, pos = 3` | `base` | `u64` | whole units of the amount |
| `body, pos = 4` | `micro` | `u64` | the `10^-6` remainder, `0..=999_999` |
| `body, pos = 5` | `su_ids` | `Vec<B256>` | the spending units consumed, as a canonical set |

```text
nft_hash = iterate(id, [owner, worldwide_day, currency, base, micro,
                        len(su_ids), su_0, …, su_n-1])
```

where `iterate(seed, xs) = fold(seed, |s, x| poseidon2([s, x]))`. The `len`
prefix is the canonical set encoding and is what makes the vector boundary
unambiguous — it is emitted even for an empty set. `su_ids` must be strictly
ascending by field value, so sorted and de-duplicated;
`outbe_zk_core::codec::sort_set` normalises it, and an unsorted set is a hash
error, not a different hash. `micro` reaching `10^6` gives one amount two
spellings; the hash does not enforce the bound, the producer must.

`tests/tribute.rs` pins the fold order, the empty-set length prefix and the
unsorted-set rejection; `examples/outbe-l2-demo/tests/roundtrip.rs` in this
workspace spells the same preimage out by hand with the bare `poseidon2` primitive and requires it
to reproduce the proof's word.

### Field fit

Every `B256` member is a BN254 scalar carried in 32 bytes, not an arbitrary
256-bit value: it must be strictly below `outbe_zk_core::codec::FR_MODULUS`.
Hashing decodes through `field_from_be_bytes_canonical`, so a value at or above
the modulus fails with `Error::NonCanonical` instead of being silently reduced
onto a different element. **An L2 must mint draft ids and SU ids as field
elements in the first place** — a Poseidon2 output, say — never as 32 random
bytes or a keccak digest. That is not a rare edge: the modulus over `2^256` is
`21888242871839275222246405745257275088548364400416034343698204186575808495617
/ 115792089237316195423570985008687907853269984665640564039457584007913129639936
= 0.189`, so a uniform 32-byte word is a field element only ~18.9% of the time
and roughly four in five keccak digests are rejected. The same rule applies on
the way back in: `outbe-l2-zk-canonical`'s `decode_public_inputs` reads each
public word through `outbe_zk_core::zkproof::decode_public_words`, which
rejects a non-canonical word rather than reducing it, and the `alloy` mirror's
`TryFrom` does the same.

### The four public words

`claims/tribute/abi.json` is the claim's contract: four `field` parameters, all
`public`, no return type.

| # | Word | What it is |
|---|------|------------|
| 0 | `owner` | the L2's owner commitment, opaque to this claim — also body position 0 of the entity |
| 1 | `nft_hash` | `TributeDraftClaim::entity_hash()` |
| 2 | `binding_hash` | `binding(sender, draft_id, host_chain_id, l2_chain_id)` |
| 3 | `merkle_root` | the root of the L2's own commitment tree — its depth and domain are in the root's `src/main.nr`, not in the claim |

A breaking change to that list is a **new claim name**, not a new version of
this one.

#### The owner commitment

How an L2 builds word 0 — and whether a nonce goes into it at all — is that
L2's own construction, and no part of this claim: the claim says only that word
0 *is* the owner, that the same value folds at body position 0 of the entity,
and that it is a canonical field element. Neither that construction nor
anything it commits to reaches L1, which takes `owner` from the draft claim it
was handed, compares word 0 against it, and never recomputes it.
`examples/outbe-l2-demo` shows one such construction, and its reviewer checklist
reads what that one root constrains over the word — as an example of the
reading, not as a rule for other roots.

### The binding

```text
binding_hash = poseidon2([BINDING_DOMAIN, sender, draft_id_lo128,
                          draft_id_hi128, host_chain_id, l2_chain_id])
```

`BINDING_DOMAIN` is `1`. Six elements: the 20-byte sender as one field, then
the draft id in two 128-bit limbs **low limb first** (independent of the
three-limb encoding `U256` amounts use), then the two chain ids. `l2_chain_id`
is the sixth element, so two L2s running byte-identical circuits still cannot
replay each other's proofs — and folding it here rather than exposing it as a
fifth public input leaves the claim at four words, and the circuit, its ABI and
its key untouched.

The circuit treats the word as opaque: the registered root only folds it into
`hash_3([nft_hash, nonce, binding_hash])` before the Schnorr check.
`tests/tribute.rs` pins the vector and pins that two L2 chain ids give
different results.

#### The three inputs the claim does not own

`binding` takes them as arguments; nothing in this crate produces them. Each is
supplied by whoever builds the witness **and independently by whoever checks the
proof**, which is the whole point — a value both sides compute from their own
copy is a value neither side can lie about (see *What a verifier must uphold* in
[`../outbe-l2-zk-canonical/README.md`](../outbe-l2-zk-canonical/README.md)).

| Input | What it is | Who supplies it | Why it is in the preimage |
|---|---|---|---|
| `sender` | 20 bytes: the account that submits the proof on the host chain. `binding` decodes it with the reducing `field_from_be_bytes`, which is exact for 20 bytes — far below `FR_MODULUS`, so no reduction happens. | The submitter builds the witness with it; the verifier uses the caller it is actually serving, not a value read out of the proof. The demo fixture uses `[0x11; 20]` (`examples/outbe-l2-demo/tests/common/mod.rs`). | A proof is a public blob and anyone who sees one can resubmit it. Folding the caller in means a proof built for one submitter does not verify as another's. |
| `host_chain_id` | A `u64`: the chain id of the L1 the claim is submitted to. | The submitter; the verifier from its own chain configuration. The demo uses `31337`. | Stops one proof being replayed against a second host chain that registered the same L2 key. |
| `l2_chain_id` | A `u64`: the chain id the key is registered under in `l2/manifest.toml` — here `57005`. | Fixed by the registration. The verifier takes it from the key lookup it already performed, not from the submitter. | Two L2s may register byte-identical circuits, which means byte-identical keys, and then nothing else in the four public words tells them apart. Folding it here rather than exposing it as a fifth public word keeps the claim at four. |

`draft_id`, the fourth argument, is the claim's own `TributeDraftClaim::id` —
the same 32 bytes that seed `nft_hash` — split into two 128-bit limbs, low limb
first.

## Surface

```rust
use outbe_l2_claims::claims::tribute::{binding, PublicInputs, TributeDraftClaim};
use outbe_l2_claims::outbe_zk_core::entity::Entity;

let nft_hash = draft.entity_hash()?;
let binding_hash = binding(&sender, &draft.id.0, host_chain_id, l2_chain_id)?;
```

| Item | What it is |
|------|------------|
| `claims::<name>::<Entity>` | The entity behind `nft_hash`, folded by `#[derive(Entity)]` |
| `claims::<name>::binding` | The `binding_hash` formula, and `BINDING_DOMAIN` beside it |
| `claims::<name>::CLAIM_NAME` | The claim's directory name, as `l2/manifest.toml` spells it |
| `claims::<name>::PUBLIC_INPUT_COUNT` | Public field words the claim exposes (tribute: 4) |
| `claims::<name>::PublicInputs` | The words in ABI order, typed from the ABI: `field` as `Fr`, unsigned `integer` as `uN`, arrays as `[T; N]` |
| `claims::<name>::public_words` | Flatten for a prover or for `encode_combined_proof` |
| `claims::<name>::from_fields` | The inverse: rebuild from ABI-ordered words. The key-free half of decoding |
| `claims::<name>::alloy::PublicInputs` | The `B256` mirror, with `TryFrom` both ways |
| `CLAIM_ABIS` | Each claim's `abi.json` as a `&'static str` plus its word count — see below |
| `outbe_zk_core` | The core, re-exported: one dependency is enough for a claim consumer |

Decoding a *combined proof* needs the verification key, because that is where
the proof length comes from, so `decode_public_inputs(combined, vk)` lives in
`outbe-l2-zk-canonical` and calls `from_fields` here.

## `CLAIM_ABIS`, and why it exists

`outbe-l2-zk-canonical`'s build script gates every committed root's public ABI
against the claim ABI. A build script cannot open another package's files by
path, so that crate takes `outbe-l2-claims` as a **build-dependency** as well as
a normal dependency and reads the contract from the crate that owns it:

```rust
// outbe-l2-zk-canonical/build.rs
for claim in outbe_l2_claims::CLAIM_ABIS {
    // claim.name, claim.abi_json (include_str!'d), claim.public_input_count
}
```

`CLAIM_ABIS` is in claim-name order, which is load-bearing: the registry
derives its `Claim` enum from it, and that enum's `Ord` is what its key table is
sorted by and what `l2_keys` binary-searches.

## Codegen

`build.rs` reads `claims/*/abi.json` and nothing else — no key, no root, no
manifest — and emits the per-claim `PublicInputs`, `public_words`,
`from_fields`, the `alloy` mirror and `CLAIM_ABIS`. It never runs `nargo` or
`bb`, so `cargo build` and `cargo test` need no Noir toolchain. Hard build
failures: a claim directory with no `abi.json`, an ABI with no `parameters`
array or an empty one, and any parameter that is not `visibility: "public"` — a
claim ABI is the public half of a Noir ABI and nothing else.

A claim ABI may use `field`, unsigned `integer`, and arrays of those. A struct
or a signed integer is a hard build failure naming the claim and the type.

## Adding a claim

Add `claims/<name>/abi.json` and a `src/claims/<name>.rs` with the entity and
its binding, then declare the module in `src/claims.rs`. `build.rs` picks the
ABI up and emits `generated::<name>`, which the hand-written module re-exports
as `claims::<name>`; `outbe-l2-zk-canonical` picks up the new `CLAIM_ABIS` row
and grows a `Claim` variant. Nothing about an existing claim changes.

By convention every claim exposes `owner`, `nft_hash` and `binding_hash` as its
first three words and `merkle_root` as its last, so ownership, binding and
inclusion are checked the same way for every NFT. The convention is a
convention: `build.rs` does not enforce it.
