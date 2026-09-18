# outbe-l2-zk-canonical

The L2 side of the Outbe zk gate. Outbe L1 admits NFTs from L2 networks by
proof: each **claim** kind has one public-input ABI, and each registered L2
holds one verification key per claim and version. Everything L2-facing lives
here — the claim entities and their bindings, the claim ABIs, the committed
circuit roots with their keys, and the build-time checks that tie them
together.

This crate has **no dependency on `outbe-zk-canonical`** (the L1 circuits) in
either direction, and none on `outbe-zk-backend`: registering an L2 cannot
touch an L1 circuit or its key, and a consumer that only hashes claims takes
this crate without taking barretenberg (see *Features*). It re-exports
`outbe_zk_core`, so a consumer that only registers or verifies claims depends
on this crate alone and still reaches `codec`, `hash`, `keys`, `Entity` and
`Error`.

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
unsorted-set rejection; `examples/outbe-l2-demo/tests/roundtrip.rs` spells the
same preimage out by hand with the bare `poseidon2` primitive and requires it
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
the way back in:
`decode_public_inputs` reads each public word through
`outbe_zk_core::zkproof::decode_public_words`, which rejects a non-canonical
word rather than reducing it.

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
copy is a value neither side can lie about (see *What a verifier must uphold*).

| Input | What it is | Who supplies it | Why it is in the preimage |
|---|---|---|---|
| `sender` | 20 bytes: the account that submits the proof on the host chain. `binding` decodes it with the reducing `field_from_be_bytes`, which is exact for 20 bytes — far below `FR_MODULUS`, so no reduction happens. | The submitter builds the witness with it; the verifier uses the caller it is actually serving, not a value read out of the proof. The demo fixture uses `[0x11; 20]` (`examples/outbe-l2-demo/tests/common/mod.rs`). | A proof is a public blob and anyone who sees one can resubmit it. Folding the caller in means a proof built for one submitter does not verify as another's. |
| `host_chain_id` | A `u64`: the chain id of the L1 the claim is submitted to. | The submitter; the verifier from its own chain configuration. The demo uses `31337`. | Stops one proof being replayed against a second host chain that registered the same L2 key. |
| `l2_chain_id` | A `u64`: the chain id the key is registered under in `l2/manifest.toml` — here `57005`. | Fixed by the registration. The verifier takes it from the key lookup it already performed, not from the submitter. | Two L2s may register byte-identical circuits, which means byte-identical keys, and then nothing else in the four public words tells them apart. Folding it here rather than exposing it as a fifth public word keeps the claim at four. |

`draft_id`, the fourth argument, is the claim's own `TributeDraftClaim::id` —
the same 32 bytes that seed `nft_hash` — split into two 128-bit limbs, low limb
first.

## What a verifier must uphold

**Everything in this section is the consumer's responsibility, not this
repository's.** This crate defines two values — `nft_hash` and `binding_hash` —
and pins them against frozen vectors in `tests/tribute.rs`. It verifies nothing, holds no chain state, and
has no way to check any obligation below on a consumer's behalf. The verifier
is `outbe-zk-backend`: `RawVerifier::verify_combined(vk_bytes, combined_proof)`
takes the key a consumer looked up and the proof it was handed and returns
`Result<bool, Error>`. That is the entry point, and
`examples/outbe-l2-demo/tests/roundtrip.rs` uses it. Checking the proof is all
it does; the obligations below remain the consumer's.

Start from what a verified proof actually says. The registered root
(`l2/57005/tribute/1.0.0/src/main.nr`) constrains only relations *among* the
four public words: that `owner` is `poseidon2([pk.x, pk.y, nonce])` for a `pk`
that is on the Grumpkin curve and is not the identity; that a Grumpkin Schnorr
signature by that same `pk` covers `poseidon2([nft_hash, nonce, binding_hash])`;
and that `nft_hash` is a leaf resolving to `merkle_root` at the root's own depth
and domain. It takes `nft_hash`, `binding_hash` and `merkle_root` as given
field elements and never asks where they came from. So a verifying proof means
*these four words are mutually consistent and the prover holds a key* — and, on
its own, nothing more than that.

Five obligations turn that into a statement about a draft:

1. **Select the key, do not accept one.** Look it up with
   `l2_keys(chain_id, Claim::Tribute)`, pick the version your policy allows,
   check `L2Key::status()`, and verify against `L2Key::vk_bytes()`. Pass that
   same key to `decode_public_inputs`. A proof verifying under a key you did not
   look up is a proof about a different circuit.
2. **Recompute `nft_hash` (word 1).** Build a `TributeDraftClaim` from your own
   copy of the draft and compare `entity_hash()` to word 1. Without this the
   proof says only that *some* draft was signed: the id, the day, the currency,
   the amount and the spending units all live inside that single word.
3. **Recompute `binding_hash` (word 2).** Call
   `binding(sender, draft_id, host_chain_id, l2_chain_id)` with your own four
   values — the caller you are serving, the draft id you just hashed, your chain
   id, and the chain id of the key you looked up in step 1 — and compare to word
   2. Without this the proof is replayable by any submitter, on any host chain
   that registered this key, and as any other L2 running the same circuit.
4. **Establish `merkle_root` (word 3) out of band.** This is the obligation this
   repository can help with least, and the easiest to get wrong. Nothing here
   stores, builds or tracks an L2's commitment tree — `outbe_zk_core::imt` is
   arithmetic and nothing else, and the depth and domain are the root's, not the
   claim's. The circuit proves `nft_hash` is under *whatever root the prover
   handed it*, so a prover that invents a tree containing its own leaf produces a
   proof that verifies against that invented root. Word 3 is only worth
   something if you accept it exclusively from a source that independently
   establishes the L2's tree history — a root that L2 published through its own
   consensus, read from a chain you trust. Taking word 3 from the proof because
   the proof verified is circular, and it is the security of the claim.
5. **Do not read `owner` (word 0) as an identity.** It is an opaque commitment
   of the L2's own making. Nothing in this crate binds it to an account, an
   address or a registration. If your rules say a particular party owns a draft, establishing
   and checking that binding is yours.

`examples/outbe-l2-demo/tests/roundtrip.rs` walks steps 1–3 end to end and
recomputes words 1 and 2 by hand with the bare `poseidon2` primitive rather than
through the claim's own helpers — which is a test that this crate agrees with
itself, not a verifier and not a substitute for one.

## Layout

```
claims/<claim>/abi.json          the claim's public-input ABI; one source of truth
l2/manifest.toml                 the append-only L2 registry
l2/<chain>/<claim>/<version>/
  Nargo.toml                     git deps tag-pinned, no path dep leaving the root
  src/main.nr                    the circuit; tree depth and domain are the L2's own
  abi.json                       nargo output, committed
  circuit.vk                     bb output, committed — the bytes L1 verifies with
  circuit.hash                   keccak256 of the compiled ACIR, committed and checked
```

`l2/manifest.toml` carries a top-level `proof_system` and one `[[l2_circuit]]`
table per registered key:

```toml
proof_system = "bb-keccak-v1"

[[l2_circuit]]
chain_id = 57005
claim = "tribute"
version = "1.0.0"
status = "active"
root = "l2/57005/tribute/1.0.0"
```

`root` is crate-relative. Bytecode is not committed: L1 never needs it and
`xtask l2 verify` regenerates it. A root is self-contained by rule — no `path`
dependency may resolve outside it, so an L2 cannot silently depend on a shared
library that later changes under it. In particular the L1 circuits' own Noir
library, `outbe_circuit_core` under `crates/outbe-zk-canonical/noir/`, is not
reachable from a root; the registered root inlines the ownership and Merkle
helpers it needs and depends only on tag-pinned `noir-lang/schnorr`.

## Generated API

`build.rs` reads the committed files and emits `crate::generated`, re-exported
where consumers should reach for it. It never runs `nargo` or `bb`, so
`cargo build` and `cargo test` need no Noir toolchain.

```rust
use outbe_l2_zk_canonical::{claims::tribute, Claim, l2_keys};

let key = l2_keys(57005, Claim::Tribute)
    .iter()
    .find(|k| k.version() == "1.0.0")
    .expect("registered");

// One decoder serves every registered key: the expected length comes from the
// key header, not from a per-circuit constant.
let public = tribute::decode_public_inputs(combined_proof, key.vk_bytes())?;
let ethereum = tribute::alloy::PublicInputs::try_from(public)?;
```

| Item | What it is |
|------|------------|
| `Claim` | One variant per `claims/<name>/abi.json`, in name order, with `as_str()` |
| `claims::<name>::CLAIM` | Which claim the module is, as a `Claim` enum constant (`pub const CLAIM: super::Claim = super::Claim::<Variant>`); the name is `CLAIM.as_str()` |
| `claims::<name>::PUBLIC_INPUT_COUNT` | Public field words the claim exposes (tribute: 4) |
| `claims::<name>::PublicInputs` | The words in ABI order, typed from the ABI: `field` as `Fr`, unsigned `integer` as `uN`, arrays as `[T; N]` (tribute: four `Fr`) |
| `claims::<name>::public_words` | Flatten for a prover or for `encode_combined_proof` |
| `claims::<name>::decode_public_inputs(combined, vk)` | Key-aware decoder |
| `claims::<name>::alloy::PublicInputs` | The `B256` mirror, with `TryFrom` both ways |
| `l2_keys(chain_id, claim)` | The registered `L2Key`s by binary search, ascending by version (`l2-keys`) |
| `L2Key::{version, status, vk_hash, vk_bytes}()` | Read-only accessors; the fields are private and there is no constructor, so a caller cannot fabricate a key (`l2-keys`) |
| `outbe_zk_core` | The core, re-exported: one dependency is enough for a claim consumer |
| `proof_words` / `combined_len` / `encode_combined_proof` | The key-derived proof layout, written once (hand-written in `src/lib.rs`) |

`L2_KEYS` is a `&'static` table built at compile time, sorted by
`(chain_id, claim)` with versions ascending, so several versions of one pair
coexist and the newest is last. An unregistered pair yields an empty slice.
There is no runtime registration path: the set of keys a node accepts changes
only with a node release.

A claim ABI may use `field`, unsigned `integer`, and arrays of those. A struct
or a signed integer is a hard build failure — the generator names the claim and
the type it will not handle.

## Features

`l2-keys`, on by default, is the registry: `L2Key`, `L2ClaimEntry`,
`CircuitStatus`, `L2_KEYS`, `l2_keys`, and each root's `circuit.vk` compiled
in. Every verifier wants it and gets it by writing nothing.

Off — `default-features = false` — the crate is still the whole claim: the
entities, `binding`, the claim ABIs, `PublicInputs`, `public_words`,
`decode_public_inputs` and the `proof_words` / `combined_len` /
`encode_combined_proof` layout helpers. That is what a consumer needs if it
only folds claims and recomputes `binding_hash` instead of verifying proofs.

What the split buys such a consumer is verifiable here: `build.rs` reads
`l2/manifest.toml` and the roots only under
`if env::var_os("CARGO_FEATURE_L2_KEYS").is_some()`, and emits the key table
only there, so with the feature off nothing an L2 registration touches reaches
the object file and the crate's compiled bytes do not move when a registration
lands.

The gate cannot creep over the claim half unnoticed: CI runs `cargo test -p
outbe-l2-zk-canonical --no-default-features` (`.github/workflows/ci.yml`), and
`the_enclaves_half_needs_no_registry` in `tests/tribute.rs` exercises the
entities, `binding`, `PublicInputs` and `public_words` through the
`outbe_zk_core` re-export with the feature off — if any of them gained a
dependency on the registry, that build would stop compiling.

## Checks at `cargo build`

The claim-ABI checks run in every build; the rest need the roots and so run
with `l2-keys` — without it `build.rs` reads `claims/*/abi.json` and nothing
else. Each is a hard build failure naming the entry:

- every non-revoked `root` exists and holds `Nargo.toml`, `abi.json` and `circuit.vk`;
- root hygiene: the package is `type = "bin"`, no `path` dependency resolves outside the root, and every git dependency carries a `tag` or `rev`;
- the root's public ABI parameters equal `claims/<claim>/abi.json` by name, type and order;
- the key is exactly 59 words — `VK_WORDS = 3 + 28 * 2`, so a committed `circuit.vk` is `59 * 32 = 1888` bytes — and its header declares `PUBLIC_INPUT_COUNT + 8` public inputs (the eight `DefaultIO` pairing-accumulator words bb appends);
- `(chain_id, claim, version)` is unique and `status` is one of `active` / `deprecated` / `revoked`;
- a `revoked` entry has no surviving root — revocation deletes it in the same pull request;
- `proof_system` is present and equals the pinned `bb-keccak-v1`.

There is no runtime `proof_system` comparison because there is nothing to
compare: an `L2Key` has private fields and no public constructor, so the only
keys in existence are the ones `build.rs` emitted under these checks.

What `build.rs` deliberately cannot check is that the committed key came from
the committed source; that needs the toolchain and is
`cargo xtask l2 verify`'s job, run in CI on every change to `l2/` or `claims/`.

## Registering an L2

1. Write `l2/<chain_id>/<claim>/<version>/` — `Nargo.toml` (`type = "bin"`, git deps pinned by tag or rev, no `path` dep leaving the directory) and `src/main.nr`.
2. `cargo xtask l2 admit --root crates/outbe-l2-zk-canonical/l2/<chain_id>/<claim>/<version>` mints `abi.json`, `circuit.vk` and `circuit.hash` and appends the manifest entry. An L2 team may instead commit the three files by hand; `verify` proves them either way.
3. `cargo xtask l2 verify --root <path>` recompiles the root with the pinned toolchain and proves the committed key reproduces byte for byte. CI runs it on the pull request.
4. A reviewer reads `src/main.nr` and checks the three things no tool can: that it constrains ownership over `owner`, signs `Poseidon2([nft_hash, nonce, binding_hash])`, and proves `nft_hash` is a leaf under `merkle_root`. *How* the root commits to `owner` is its own construction, not something to check against a formula here; `examples/outbe-l2-demo/README.md`'s reviewer checklist works one root through.

A key is a deterministic function of the compiled ACIR and the `bb` version,
and the ACIR is a deterministic function of the root's source, its tag-pinned
dependencies and the `nargo` version. Both tool versions are pinned once, in
`mise.toml`, and there is no per-entry pin; `verify` and `admit` refuse to run
under any other pair. A toolchain bump is therefore the only change that can
stop a committed key reproducing, which is why it re-verifies everything.

### Who may register a `chain_id`

Nobody in particular, and the registry does not pretend otherwise.

`admit` derives `chain_id`, `claim` and `version` from the `--root` path and
from nothing else (`xtask/src/l2.rs`). The only uniqueness rule anywhere in the
pipeline is that `(chain_id, claim, version)` must not already appear in
`l2/manifest.toml` — checked in `build.rs` and again in `verify`. No
registration is signed. No key, account or prior claim is attached to a chain
id. Nothing checks that whoever opens the pull request has any relationship to
the chain the path names, and a chain id that is already registered can gain a
new version from a different pull request.

So a merged registration establishes exactly four things, all of them
machine-checked and all of them about *bytes*, not about people:

- the committed `circuit.vk` is the key the committed `src/main.nr` compiles to
  under the pinned `nargo` and `bb` (`cargo xtask l2 verify`);
- `circuit.hash` is `keccak256` of that same compiled ACIR;
- the root is self-contained — `type = "bin"`, no `path` dependency leaving it,
  every git dependency tag- or rev-pinned — and its public ABI is the claim's;
- the `(chain_id, claim, version)` triple was unused.

It does **not** establish authorship. "What proves this circuit is mine" has no
answer in this repository: the only thing standing behind a `chain_id` is that a
human reviewer approved a pull request. Whatever identity that carries comes
from the hosting platform's review and branch-protection settings, which live
outside this tree and which this file therefore cannot describe. Read
`l2/manifest.toml` as a list of circuits some reviewer accepted — not as
evidence that the L2 named in a path asked for the entry.

### What `admit` does

`admit` derives `chain_id`, `claim` and `version` from the `--root` path
itself, which must be `l2/<chain_id>/<claim>/<version>` with a three-part
version — there are no `--chain` / `--claim` / `--version` flags to disagree
with it. It refuses if the manifest already has that triple or that root
string, and it refuses if `abi.json`, `circuit.vk` or `circuit.hash` already
exists in the root: a merged root is immutable, so bump the version. It then
runs hygiene, the toolchain assertion and the compile, checks the *compiled*
ABI against the claim ABI, writes the three artifacts, appends the entry with
`status = "active"`, and prints the `verify` command to run next.

### What `verify` proves, in order

`cargo xtask l2 verify` takes exactly one of `--root PATH`, `--changed
[--base REF]` or `--all`. Everything that needs no toolchain runs first, so a
`nargo` or `bb` failure can never stand in for a defect a plain file read would
have named.

1. Load `l2/manifest.toml`, reject a duplicate `(chain_id, claim, version)`, reject any `revoked` entry whose root still exists, then select the entries. `--root` on a revoked entry explains the revocation instead of reporting a missing directory.
2. Assert the toolchain once, before any root: `nargo` and `bb` report the `mise.toml` pins, and `l2/manifest.toml`'s `proof_system` equals `crates/outbe-zk-canonical/circuits/manifest.toml`'s.

Then, per root:

3. Hygiene — the directory exists, `Nargo.toml` parses, `[package] type = "bin"`, `src/main.nr` exists, no `path` dependency escapes the root, every git dependency carries a `tag` or `rev`.
4. The committed `abi.json`'s public parameters equal `claims/<claim>/abi.json`, **before** anything is compiled.
5. Copy the root to `target/xtask-l2/` and run `nargo compile`, then `bb write_vk`.
6. The committed `abi.json` equals the compiled ABI. The comparison is structural, over parsed JSON, not a raw-string compare — that would false-positive on serializer differences. The compiled ABI matching the claim ABI follows by transitivity from step 4. On a mismatch the compiled ABI is written beside the scratch copy so the reviewer can diff it.
7. The committed `circuit.vk` equals the recompiled key, byte for byte.
8. The committed `circuit.hash` equals `keccak256(ACIR)`.

It prints `circuit_hash` and `vk_hash` and writes nothing into the root or the
manifest.

`--changed` selects every live entry with a file changed inside its own root or
in its claim ABI. A change to `mise.toml`, the workspace `Cargo.toml` or
`crates/outbe-zk-canonical/circuits/manifest.toml` widens the selection to every
live entry, since any of the three can stop a key reproducing. A
`l2/manifest.toml` edit widens it only through *added* `root = "..."` lines — a
status flip adds no root and selects nothing extra.

## What a merged root may change

A merged root is pinned to its key, not frozen as bytes. Its contents may
change only in ways that leave the compiled ACIR and `circuit.vk`
byte-identical, and `cargo xtask l2 verify` proves that by re-deriving both
from `src/`. That is why a test-only edit is permitted: `#[test]` functions are
not part of the binary's ACIR, so they cannot move the key — and the permission
rests on `verify` re-deriving it, not on the claim that they cannot. The
registered root carries a `#[test]` module below its constraint body for
exactly this reason.

A constraint fix does move the key, and so does a different private witness. It
is a new version directory and a new entry; the old one becomes `deprecated`.
A different public-input list is a different claim, not a version.

`version` is the L2's own semver and is part of the key's identity. Status
decides what reaches the table: `active` and `deprecated` entries are both
generated into `L2_KEYS` and both verified and `nargo test`-ed, and the only
difference this crate draws between them is the value `L2Key::status()`
returns. `revoked` drops the entry from the table and requires the root to be
gone.

## Adding a claim

Add `claims/<name>/abi.json` and a `src/claims/<name>.rs` with the entity and
its binding. `build.rs` picks up the ABI and emits `generated::<name>` with
`PublicInputs`, `public_words`, the decoder, the alloy mirror and the `Claim`
variant; the hand-written module re-exports them as `claims::<name>`. Nothing
about an existing claim changes. By convention every claim exposes `owner`,
`nft_hash` and `binding_hash` as its first three words and `merkle_root` as its
last, so ownership, binding and inclusion are checked the same way for every
NFT. The convention is a convention: `build.rs` does not enforce it.
