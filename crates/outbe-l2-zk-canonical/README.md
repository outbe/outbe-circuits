# outbe-l2-zk-canonical

The L2 registry of the Outbe zk gate. Outbe L1 admits NFTs from L2 networks by
proof: each **claim** kind has one public-input ABI, and each registered L2
holds one verification key per claim and version. The keys live here — the
committed circuit roots, the `l2/manifest.toml` that indexes them, the
key-aware decoders and the build-time checks that tie them to the claim ABIs.

This crate has **no dependency on `outbe-zk-canonical`** (the L1 circuits) in
either direction, and none on `outbe-zk-backend`: registering an L2 cannot
touch an L1 circuit or its key, and a verifier takes this crate without taking
barretenberg. It re-exports both `outbe_l2_claims` and `outbe_zk_core`, so a
consumer that registers or verifies claims depends on this crate alone and
still reaches the claim entities, `binding`, `codec`, `hash`, `keys`, `Entity`
and `Error`.

## The claim contract

The claim itself — `TributeDraftClaim`, `binding`, `BINDING_DOMAIN`,
`claims/tribute/abi.json` and the generated `PublicInputs` — is
[`outbe-l2-claims`](../outbe-l2-claims), which this crate depends on and
re-exports through `claims::<name>`. The fold order, the field-fit rule, the
four public words and the binding preimage are documented in
[`../outbe-l2-claims/README.md`](../outbe-l2-claims/README.md), and the frozen
vectors for all of them are that crate's `tests/tribute.rs`.

The split is the guarantee: the dependency runs one way, so a consumer that
only folds claims takes that crate and no verification key can reach its binary
under any cargo invocation. It used to be a default-on `l2-keys` cargo feature
on one crate, and a feature cannot carry it — cargo unifies features across the
selected package set.

## What a verifier must uphold

**Everything in this section is the consumer's responsibility, not this
repository's.** `outbe-l2-claims` defines two values — `nft_hash` and
`binding_hash` — and pins them against frozen vectors in its `tests/tribute.rs`.
Neither crate verifies anything, holds chain state, or has any way to check an
obligation below on a consumer's behalf. The verifier
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

`build.rs` reads `l2/manifest.toml`, the roots, and the claim ABIs it gets from
`outbe_l2_claims::CLAIM_ABIS`, and emits `crate::generated`, re-exported where
consumers should reach for it. It never runs `nargo` or `bb`, so `cargo build`
and `cargo test` need no Noir toolchain.

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
| `Claim` | One variant per claim ABI, in claim-name order, with `as_str()` |
| `claims::<name>::CLAIM` | Which claim the module is, as a `Claim` enum constant; the name is `CLAIM.as_str()` |
| `claims::<name>::decode_public_inputs(combined, vk)` | Key-aware decoder. Here rather than in `outbe-l2-claims` because the expected proof length comes from the key; it calls that crate's `from_fields` |
| `claims::<name>::*` | Everything else under the module is `outbe-l2-claims` re-exported: the entity, `binding`, `PUBLIC_INPUT_COUNT`, `PublicInputs`, `public_words`, `from_fields` and the `alloy` mirror |
| `l2_keys(chain_id, claim)` | The registered `L2Key`s by binary search, ascending by version |
| `L2Key::{version, status, vk_hash, vk_bytes}()` | Read-only accessors; the fields are private and there is no constructor, so a caller cannot fabricate a key |
| `outbe_l2_claims` / `outbe_zk_core` | The claim contract and the core, re-exported: one dependency is enough for a verifier |
| `proof_words` / `combined_len` / `encode_combined_proof` | The key-derived proof layout, written once (hand-written in `src/lib.rs`) |

`L2_KEYS` is a `&'static` table built at compile time, sorted by
`(chain_id, claim)` with versions ascending, so several versions of one pair
coexist and the newest is last. An unregistered pair yields an empty slice.
There is no runtime registration path: the set of keys a node accepts changes
only with a node release.

## Checks at `cargo build`

Every build runs all of them; nothing here is behind a feature. Each is a hard
build failure naming the entry:

- every non-revoked `root` exists and holds `Nargo.toml`, `abi.json` and `circuit.vk`;
- root hygiene: the package is `type = "bin"`, no `path` dependency resolves outside the root, and every git dependency carries a `tag` or `rev`;
- the root's public ABI parameters equal the claim ABI by name, type and order — read from `outbe_l2_claims::CLAIM_ABIS`, since a build script cannot open another package's files by path, which is why `outbe-l2-claims` is a build-dependency as well as a normal one;
- the key is exactly 59 words — `VK_WORDS = 3 + 28 * 2`, so a committed `circuit.vk` is `59 * 32 = 1888` bytes — and its header declares `PUBLIC_INPUT_COUNT + 8` public inputs (the eight `DefaultIO` pairing-accumulator words bb appends);
- `(chain_id, claim, version)` is unique and `status` is one of `active` / `deprecated` / `revoked`;
- a `revoked` entry has no surviving root — revocation deletes it in the same pull request;
- `proof_system` is present and equals the pinned `bb-keccak-v1`.

There is no runtime `proof_system` comparison because there is nothing to
compare: an `L2Key` has private fields and no public constructor, so the only
keys in existence are the ones `build.rs` emitted under these checks.

What `build.rs` deliberately cannot check is that the committed key came from
the committed source; that needs the toolchain and is
`cargo xtask l2 verify`'s job, run in CI on every change to `l2/` or to a claim ABI.

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
4. The committed `abi.json`'s public parameters equal `outbe-l2-claims`'s `claims/<claim>/abi.json`, **before** anything is compiled.
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

The claim itself is added in [`outbe-l2-claims`](../outbe-l2-claims) — see that
crate's README. Here, nothing: `build.rs` picks the new `CLAIM_ABIS` row up and
grows a `Claim` variant and a `claims::<name>` module. Nothing about an existing
claim or an existing key changes.
