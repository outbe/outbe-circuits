# outbe-l2-demo

The reference implementation an L2 team clones: the Rust side of one registered
tribute circuit root,
[`crates/outbe-l2-zk-canonical/l2/57005/tribute/1.0.0/`](../../crates/outbe-l2-zk-canonical/l2/57005/tribute/1.0.0).

Chain 57005 is an ordinary registration — the demo goes through the same
registry, the same build-time checks and the same `xtask l2 verify` a real L2
does. Nothing here depends on `outbe-zk-canonical`; an L2 has no business with L1
circuits, and the dependency graph says so. The crate depends on
`outbe-l2-zk-canonical` (claims and keys), `outbe-zk-core` (hashes, keys, tree)
and `outbe-zk-backend` (proving). Two tests read a committed L1 *file* by path
— the L1 manifest, to check the proof-system pins, and one L1 verification key,
to show a tribute proof is rejected under that one foreign key (not under every
possible key — see *Partly covered* at the end) — which adds no crate, no type
and no call.

```
build.rs               Witness + circuit identity, generated from the root's abi.json
resources/bytecode.b64 the root's ACIR (L2 roots commit no bytecode; proving needs it)
src/lib.rs             DEPTH, TREE_DOMAIN, empty_tree, prove_tribute
src/draft.rs           a richer L2-side TributeDraft and its projection onto the claim
tests/roundtrip.rs     prove + verify against the registered key (one proof, six claims)
tests/witness.rs       ACVM solve against the real ACIR, witness layout, prover contract
tests/proof_system.rs  the bb / barretenberg-rs / proof_system pins agree
tests/reproduce.rs     #[ignore] — the root reproduces its key (needs nargo + bb)
tests/common/mod.rs    the fixture draft, signer and binding the tests share
benches/proving.rs     prove / prove_low_memory / verify cost
```

`build.rs` is self-contained — `serde_json`, `base64` and `tiny-keccak`, no
Noir toolchain. It reads the root's `abi.json` into the `Witness` type and its
`EmbeddedCurvePoint`, hashes the root's `circuit.vk` into the `TributeDemo`
circuit identity, and asserts that `keccak256` of the ACIR in
`resources/bytecode.b64` equals the root's committed `circuit.hash`. A proof
against some other ACIR would not be a proof of the registered circuit.

## The Rust side

`src/draft.rs` holds `TributeDraft`, the L2's own richer record with its
`SpendingUnit`s, and `TributeDraft::claim()`, the projection onto
`TributeDraftClaim`. That split is the shape to copy: the L2 keeps whatever
bookkeeping it likes, and exactly one function narrows it to the consensus
struct.

`src/lib.rs` holds the tree constants and the prover. `DEPTH` is 32 and
`TREE_DOMAIN` is `"OUTBE_FULL_CIRCUIT"`, whose `ascii_field` image is the
domain the root hardcodes — both are this L2's own, not the claim's.

`prove_tribute(rng, claim, signer, binding, path)` refuses before it proves.
It rejects a path of the wrong depth or domain; it recomputes the owner
commitment from the signer and returns `Error::OwnerMismatch` rather than
proving a witness the circuit would reject; then it signs
`poseidon2([nft_hash, nonce, binding_hash])`, recomputes `merkle_root` from the
path, and returns the `Witness` and the `PublicInputs`.

## Reviewer checklist

A registration is admitted by a pull request. The machine proves the *key* came
from the *source*; it cannot prove the source says the right thing. That is the
whole reviewer job. Below are the three constraints *this* root carries, read
against its
[`src/main.nr`](../../crates/outbe-l2-zk-canonical/l2/57005/tribute/1.0.0/src/main.nr)
— a worked example of the reading, not a template another root must match.

**1. Ownership over `owner` (public word 0).** How a root commits to the key
behind word 0 is that L2's own construction and no part of the claim
(`outbe-l2-zk-canonical/README.md`, *The owner commitment*), so there is no
formula to check a root against here. What a reviewer checks is that the root
binds word 0 to a key the prover holds, and that the L2's own Rust side builds
word 0 the same way. This root commits `poseidon2([pk.x, pk.y, nonce])` for a
`pk` that is on the Grumpkin curve and is not the identity, inside
`verify_ownership_per_su`:

```noir
assert(!pk.is_infinite(), "pk is the Grumpkin identity point");
assert(pk.y * pk.y == x_cubed - 17, "pk is not on the Grumpkin curve (y^2 != x^3 - 17)");
assert(computed_owner == owner, "owner mismatch: Poseidon3(pk, nonce) != public owner");
```

A root that commits to a curve point and omits the curve check accepts a forged
`pk`. The Rust side of this one is `derive_owner` in `prove_tribute`
([`src/lib.rs`](src/lib.rs)), which refuses to prove a witness whose `owner`
does not match; `tests/witness.rs` pins the pair.

**2. The signed message.** A Grumpkin Schnorr signature by that same `pk` over
`poseidon2([nft_hash, nonce, binding_hash])` — and nothing else:

```noir
let pre_hash_fr: Field = hash_3([nft_hash, nonce, binding_hash]);
let pre_hash_bytes: [u8; 32] = pre_hash_fr.to_be_bytes();
let signature_ok = verify_schnorr_grumpkin(pk, signature, pre_hash_bytes);
```

Dropping `binding_hash` from the preimage makes a proof replayable under another
caller, draft, host chain or L2 — `binding_hash` is where `l2_chain_id` is
folded, so it is the only thing separating two L2s running byte-identical
circuits.

**3. Inclusion of `nft_hash` under `merkle_root` (public word 3).** The leaf is
`nft_hash` itself, and the recomputed root must equal word 3 at *this root's*
depth and domain:

```noir
let computed_merkle_root = merkle_root_from_indices(
    TREE_DOMAIN, nft_hash, merkle_path_siblings, merkle_path_indices,
);
assert(computed_merkle_root == merkle_root, "merkle_root mismatch: inclusion proof failed");
```

Depth (32) and the domain constant are the L2's own, not the claim's: nothing
in this repository fixes them, and two L2s need not agree. So there is no
authority to check them against — what to check is *internal agreement* between
the circuit and the tree that feeds it. The root's `TREE_DOMAIN` global and its
`[Field; 32]` / `[bool; 32]` path parameters must equal the depth and domain the
L2's own tree code builds with; in this crate that is `DEPTH` and `TREE_DOMAIN`
in [`src/lib.rs`](src/lib.rs), and `tests/witness.rs` pins the pairing by
rejecting a path built at `DEPTH - 1` or under another domain. A root whose
depth or domain differs from the producing tree proves inclusion under a root
that tree can never emit — the constraint passes and admits nothing real.

## What the machine already covers, so you do not have to

| Claim | Checked by | When |
| --- | --- | --- |
| The four public words and their order | `outbe-l2-zk-canonical/build.rs` against `claims/tribute/abi.json` | every `cargo build` with the default `l2-keys` feature |
| Root hygiene: `type = "bin"`, no `path` dep leaving the root, git deps pinned | `outbe-l2-zk-canonical/build.rs`, and again in `cargo xtask l2 verify` | every `cargo build` with the default `l2-keys` feature; `cargo xtask l2 verify` either way |
| The committed key reproduces from the committed source | `cargo xtask l2 verify` | the `l2-verify` CI job |
| The committed `circuit.hash` is `keccak256` of that recompiled ACIR | `cargo xtask l2 verify` | the `l2-verify` CI job |
| The key the demo proves with is the registered key | `tests/roundtrip.rs` | `cargo test` |
| The ACIR this crate carries is the root's | `build.rs` (`keccak256(ACIR) == circuit.hash`) | every `cargo build` |
| The witness layout matches the root's ABI | `tests/witness.rs` (ACVM solve against the real ACIR) | `cargo test` |
| `nft_hash` and `binding_hash` recomputed from the claim equal the proof's words | `tests/roundtrip.rs` | `cargo test` |
| The `bb`, `barretenberg-rs` and `proof_system` pins agree | `tests/proof_system.rs` | `cargo test` |

The recomputation in `roundtrip.rs` is deliberately independent: it folds the
two preimages by hand with the bare `poseidon2` primitive, calling neither
`entity_hash` nor `binding` nor `TributeDraft::claim`, so a bug in the claim
code cannot cancel itself out.

`tests/roundtrip.rs` is one test rather than six, because every assertion in it
shares a single `bb` proof, which dominates the test's runtime. The six are: the
registered key equals the key the demo proves under, the proof verifies, its
combined encoding decodes back to the same `PublicInputs`, a tampered word does
not verify, the same proof does not verify under another circuit's key (see
*Partly covered* below), and the hand-folded preimages reproduce public words 1
and 2.

## Running it

```sh
cargo test -p outbe-l2-demo                 # no Noir toolchain needed
cargo test -p outbe-l2-demo -- --ignored    # runs only the reproduction (nargo + bb)
cargo xtask l2 verify --root crates/outbe-l2-zk-canonical/l2/57005/tribute/1.0.0
```

`tests/reproduce.rs` is `#[ignore]`d unconditionally and no CI job passes
`--ignored`: it shells out to that same `cargo xtask l2 verify`, which the
`l2-verify` job runs directly. It is here so an L2 team can run the admission
gate from `cargo test` before opening a pull request. Everything else builds
from committed artifacts, which is why the first command needs no toolchain.

`cargo xtask l2 verify` needs `nargo` and `bb` at the versions `mise.toml`
pins; `mise install` fetches exactly those.

## Registering your own L2

1. Write `crates/outbe-l2-zk-canonical/l2/<chain_id>/tribute/1.0.0/{Nargo.toml,src/main.nr}`.
   Root hygiene is a rule: `type = "bin"`, git deps pinned by `tag` or `rev`, no
   `path` dependency leaving the root. This root is the one to compare against —
   it inlines the ownership and Merkle helpers so it depends on nothing in this
   repository, and its only dependency is tag-pinned `noir-lang/schnorr`.
2. `cargo xtask l2 admit --root <path>` writes `abi.json`, `circuit.vk`,
   `circuit.hash` and the manifest entry. It derives the chain id, claim and
   version from the path, so the path must be
   `l2/<chain_id>/<claim>/<version>`, and it refuses a root that already holds
   any of the three artifacts.
3. Copy this crate, point its `build.rs` at your root, and keep the tests.
   Replace `resources/bytecode.b64` too: a root commits no bytecode but proving
   needs it, so copy your root's ACIR there — it is the `bytecode` string from
   `nargo compile`'s `target/<package>.json`, verbatim. `build.rs` fails the
   build unless `keccak256` of it equals the root's committed `circuit.hash`.
   The depth and domain constants in `src/lib.rs` are yours to change, and so is
   the owner commitment — `prove_tribute` recomputes it with `derive_owner`, and
   an L2 that commits word 0 differently changes that, the root's
   `verify_ownership_per_su` and `tests/witness.rs` together. The claim —
   `TributeDraftClaim`, `binding` and the four public words — is not yours to
   change.
4. Open the pull request. A merged root is pinned to its key: it may change
   afterwards only where the compiled ACIR and `circuit.vk` stay byte-identical,
   which `cargo xtask l2 verify` proves by re-deriving the key from `src/`. A
   constraint fix moves the key and is a new version directory; a different
   public-input list is a different claim.

**Partly covered:** "a proof under a different key fails". `tests/roundtrip.rs`
runs the tribute proof against an L1 key read as raw bytes and requires a
rejection, but every committed key in this repo belongs to a *different*
circuit, so bb rejects on the proof length its header declares and the pairing
check is never reached. A second registered L2 root of the same shape is what
would test key binding itself.
