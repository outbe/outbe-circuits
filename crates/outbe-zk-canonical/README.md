# outbe-zk-canonical

[![crates.io](https://img.shields.io/crates/v/outbe-zk-canonical.svg)](https://crates.io/crates/outbe-zk-canonical)
[![release](https://img.shields.io/github/v/release/outbe/outbe-circuits.svg)](https://github.com/outbe/outbe-circuits/releases)
[![CI](https://github.com/outbe/outbe-circuits/actions/workflows/ci.yml/badge.svg)](https://github.com/outbe/outbe-circuits/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

The **L1 side** of the Outbe protocol: the two canonical circuits — Emit mint and
Paynote — as concrete Rust witness, public-input and combined-proof types, their
Rust hash mirrors, and the **in-code, append-only circuit registry**: the
authoritative record of every released circuit version and its on-chain identity.

This crate has no concept of an L2. Which key an L2 chain verifies with lives
entirely in [`outbe-l2-zk-canonical`](../outbe-l2-zk-canonical), which this crate
does not depend on, and which does not depend on this one.

Alloy support is optional and off by default, and `decode_public_inputs` is not
what it gates: that decoder is generated unconditionally (`build.rs`, no `cfg`)
and always returns the field-element `PublicInputs`, whatever features are on.
`features = ["alloy"]` adds two things. First, the generated
`noir::<module>::alloy` module — `PublicInputs` and `Witness` mirrors typed as
`Address` / `B256` / `U256`, with checked `TryFrom` in both directions — behind
`#[cfg(feature = "alloy")]`. Second, the alloy-typed hash helpers in
`emit_mint::hash` and `paynote::hash` (`note_sn`, `note_commitment` and their
neighbours), which take `Address` and `U256` instead of bytes and limbs. To go
from a decoded `PublicInputs` to Ethereum types, convert through that mirror;
the decode itself never needed the feature. The always-available `_raw` helpers
take `[u8; 20]`
addresses and `[Field; 3]` amount limbs instead; serials, keys and results are
field elements either way. Limb conversions live in
`outbe_zk_core::codec::{u256_limbs_be, u256_from_limbs_be, fields_from_u256}`.
Generated witness types keep their ABI layout, three `[120, 120, 16]`-bit limbs
per amount included.

## Emit mint statement

`outbe.emit.mint@1.5.0` proves knowledge of a private note amount, spend key,
depth-32 Merkle leaf index, and authentication path for a note committed under a
public chain root. Its public statement is:

| Input | Meaning |
|---|---|
| `chain_id` | Chain containing the single Emit instance. |
| `root` | Accepted depth-32 note-commitment root. |
| `nullifier` | Deterministic identifier consumed to prevent a second mint. |
| `note_owner` | 20-byte owner identity bound into the private note serial. |
| `mint_units` | Public 256-bit amount being minted from the private note. |
| `change_commitment` | Commitment to unminted value, or zero for a full mint. |

The private witness is the 256-bit `note_amount`, `note_spend_key`, `leaf_index`,
and `auth_path`. The circuit checks:

1. `0 < mint_units <= note_amount`, with a nonzero spend key and nullifier.
2. The owner and spend key derive the note serial.
3. The chain, serial, and hidden amount derive a nonzero note commitment included
   under `root` through the supplied depth-32 path.
4. The note commitment and spend key derive the published `nullifier`.
5. A partial mint rotates the spend key through that nullifier and publishes the
   exact commitment for `note_amount - mint_units`; a full mint publishes zero.

Every Emit preimage is tagged with `Poseidon2(EMIT_DOMAIN, TAG)`, where `TAG` is
a base purpose tag from `outbe_circuit_core::tags` (`COMMITMENT`, `NULLIFIER`,
`NOTE_SN`, `CHANGE_KEY`, `EMPTY`). Merkle inner nodes use
`Poseidon2(EMIT_DOMAIN, left, right)`.
`leaf_index` is converted to little-endian path bits by
`outbe_circuit_core::merkle_tree::merkle_root` in the shared Noir library, which
the Emit helper wraps: zero selects the current node as left; one selects it as
right.

### Amount encoding (256-bit)

Amounts are `noir-bignum`'s `U256` — three little-endian limbs of radix 2^120
(`limbs[0..2] < 2^120`, `limbs[2] < 2^16`) — crossing the ABI as `[u128; 3]`.
Alloy `U256` conversions live in `outbe_zk_core::codec`
(`u256_limbs_be` / `u256_from_limbs_be` / `fields_from_u256`).
Two encoding rules are load-bearing:

- **Canonicality is enforced in-circuit.** The ABI carries raw `u128` limbs with
  no range check; `U256::validate_in_range` in `main` is the gate that makes the
  limb-wise ordering, subtraction, and hashing mean what they claim.
- **The commitment hashes limbs, not a folded field element.** A 256-bit amount
  does not fit the 254-bit proving field: folding would alias amounts differing
  by the field modulus. The preimage is
  `(chain_id, serial, limbs[0], limbs[1], limbs[2])`.

`hash_multi` seeds its state with the preimage length before absorbing the
values (`outbe_zk_core::shielded_pool::hash_multi`), so two preimages of
different arity cannot collide under one tag whatever the domain — a 3-element
and a 5-element commitment preimage land on different elements by construction.

What the earlier `emit_mint` versions hashed is **not checkable from this
repository**, and no claim here should be read as if it were. `1.4.0` and
`1.4.1` are `deprecated` in `circuits/manifest.toml`, and the storage policy
below drops a deprecated version's `bytecode.b64` and `abi.json`:
`resources/circuits/emit_mint/1.4.0/` and `.../1.4.1/` hold `circuit.vk` and
nothing else. There is no older formula in the tree to compare 1.5.0 against.

**The contract a runtime upholds** (this crate cannot check it): a note
commitment is provable only under the circuit version whose formula produced it.
A runtime holding leaves committed under an earlier `emit_mint` must establish
that version's commitment formula from its own records — the deprecated entry's
`circuit_hash` in the manifest identifies the version, not the formula — and
migrate them before those notes can be minted under 1.5.0.

The circuit does **not** select or authenticate the payout recipient and does not
mutate ledger state. The verifier/runtime must bind `chain_id`, accept the
supplied root, reject a previously consumed nullifier, record any change
commitment, and authorize and execute the payout.

## Paynote statement

`outbe.paynote@1.2.0` proves the right to spend part or all of a private ERC20
payment note committed under a public chain root, without revealing the note's
total value. The note is a **bearer instrument**: spend authority is knowledge of
`note_spend_key`. There is no committed owner identity, no spender allow-list, and no
action tag — the pool contract validates and routes those.

| Input | Meaning |
|---|---|
| `chain_id` | Chain containing the pool. |
| `root` | Accepted depth-32 note-commitment root. |
| `nullifier` | Deterministic identifier consumed to prevent a second spend. |
| `asset` | ERC20 token address the note is denominated in. |
| `owner` | Address authorized to receive the payout (`msg.sender`). |
| `spend_amount` | Public 256-bit amount being spent from the private note. |
| `change_commitment` | Commitment to unspent value, or zero for a full spend. |

The private witness is the 256-bit `note_amount`, `note_spend_key`,
`leaf_index`, and `auth_path`. Amounts cross the ABI as noir-bignum `U256`
limbs (`[u128; 3]`, little-endian radix $2^{120}$); both public and private
limbs are constrained in-circuit to the canonical range $1..2^{256}-1$.
The circuit checks:

1. `asset` and `owner` are in-range (160-bit) addresses and nonzero.
2. `0 < spend_amount <= note_amount`, with a nonzero spend key and nullifier.
3. The spend key derives the note serial.
4. The chain, serial, asset, and three hidden amount limbs derive a nonzero
   note commitment included under `root` through the supplied depth-32 path.
   Hashing limbs independently avoids aliases from folding 256 bits into the
   254-bit proving field. The pool contract can build the same deposit leaf
   from the transfer it actually performed.
5. The commitment and spend key derive the published `nullifier`. Deriving it
   from the commitment rather than the serial gives exactly one nullifier per
   leaf, so two leaves sharing a serial stay independently spendable.
6. A partial spend rotates the spend key through that nullifier and publishes
   the exact commitment for `note_amount - spend_amount`, inheriting the same
   asset; a full spend publishes zero.

Every Paynote preimage is tagged with `Poseidon2(PAYNOTE_DOMAIN, TAG)`, where
`TAG` is a base purpose tag from `outbe_circuit_core::tags` (`COMMITMENT`,
`NULLIFIER`, `NOTE_SN`, `CHANGE_KEY`, `EMPTY`). Merkle inner nodes use
`Poseidon2(PAYNOTE_DOMAIN, left, right)` and the empty leaf is
`hash_multi(tag(PAYNOTE_DOMAIN, EMPTY), [chain_id])`.

### Runtime obligations

The circuit cannot enforce any of these, and each is a real vulnerability if
missed:

- **Pay out to the public `owner`, or require `msg.sender == owner`.**
  Binding `owner` into the public inputs stops *redirection*, but the proof is
  freely *transferable* — anyone can submit it verbatim. A contract that pays
  `msg.sender` instead hands the entire `spend_amount` to the first front-runner.
- Derive the deposit leaf from the asset and amount actually transferred:
  `leaf = hash_multi(tag(PAYNOTE_DOMAIN, COMMITMENT), [chain_id, serial, asset,
  amount_limb_0, amount_limb_1, amount_limb_2])`, where `serial` is supplied by
  the depositor. This binds the full 256-bit deposited value to the note;
  accepting a caller-supplied leaf makes the pool drainable.
- Deduplicate deposits on the **leaf**, not the serial. An identical
  `(key, asset, amount)` would otherwise produce a second leaf sharing one
  nullifier, permanently locking it up. Deduplicating on the serial instead
  reintroduces a griefing vector, since a serial is public in the mempool.
- Insert leaves only via those two paths (deposit, and a spend's
  `change_commitment`), and skip insertion entirely when `change_commitment` is
  zero.
- Bind `chain_id`, accept `root` only from the history it produced, and own its
  nullifier set. Nothing in the public inputs identifies the pool, so two
  deployments sharing a chain must not share roots.

### Privacy limits

- This hides **which** note was spent, not **how much** it held. Deposits are
  public and `spend_amount` is public, so `note_amount` is private only relative
  to the anonymity set of same-asset leaves under `root`. Uniform deposit
  denominations are the lever if amount privacy matters.
- The change note is reachable by **any holder of the parent spend key**, not
  only by whoever created the note: `change_key` derives from the spend key and
  the *public* nullifier, so a key disclosed once unlocks every descendant note.
  There is no forward secrecy.

## What the build produces

`cargo build` runs `build.rs`, which is **read-only** — it does **not** run
`nargo`/`bb`. It reads the committed frozen artifacts and emits, into
`outbe_zk_canonical::noir`:

- `pub mod <module> { … }` for the **latest active** version of each circuit —
  `Witness` / `PublicInputs` types, the `Circuit` + `CircuitId` impls on a
  marker, and identity consts (`LABEL`, `VERSION`, `CIRCUIT_HASH`, `BYTECODE_B64`,
  `VK_BYTES`, `VK_HASH`). This is the prover-facing API.
- `pub const CIRCUIT_REGISTRY: &[RegistryEntry]` over every **non-revoked**
  version (the verification view — VK + hashes, no bytecode). A verifier dispatches on this:
  match a submission's `circuit_id` (`vk_hash` / `label@version`), check `status`,
  verify against `vk_bytes`. Old + new versions coexist here, so a chain can accept
  both during a rollout.

So: **registry = every non-revoked version; codegen = latest active**.

## Rust hash mirrors

`emit_mint::hash` and `paynote::hash` re-implement each circuit's formulas in
Rust, so a runtime can build the same leaves, serials, nullifiers and change
commitments the circuit constrains without running a prover. Each module doc
names the `.nr` file it mirrors. The shared rules:

- `h2(a, b)` / `h3(a, b, c)` are Noir's `hash_2` / `hash_3` — the
  `outbe-poseidon` sponge at `len = 2` / `len = 3`.
- `hash_multi(tag, values)` absorbs the tag, the tuple arity, then the ordered
  values.
- Every purpose tag is domain-folded — `h2(<DOMAIN>, base)` with the base tags
  from `outbe_circuit_core::tags` — so no two domains collide on the same
  purpose.
- Merkle inner nodes are `h3(<DOMAIN>, left, right)`. `EMIT_DOMAIN` is the
  big-endian ASCII `OUTBE_EMIT`, `PAYNOTE_DOMAIN` the ASCII `OUTBE_PAYNOTE`.
- A field word must be a canonical 32-byte big-endian encoding; one that would
  need reduction is invalid input.

The mirrors are Rust; nothing here proves them equivalent to the circuit. Each
module's doc comment names the `.nr` file it must track, and that pairing is what
a reviewer checks.

## Layout

```
circuits/manifest.toml                       # append-only registry index
resources/circuits/<module>/<version>/       # frozen, immutable artifacts
    bytecode.b64   # ACIR — proving artifact (active only)
    abi.json       # drives the Rust witness types (active only)
    circuit.vk     # UltraHonkKeccak VK — verification (kept while not revoked)
noir/                                        # the .nr sources = the "head" (next version)
```

`manifest.toml` is the source of truth: a global `proof_system` (the bb pin) plus
one `[[circuit]]` per `(module, version)` with `label`, `status`, and — once the
bytecode is dropped — the preserved `circuit_hash`.

## Lifecycle & storage policy

| status | accepts proofs? | bytecode + abi | vk | in `CIRCUIT_REGISTRY`? |
|---|---|---|---|---|
| `active` | yes | kept (provable) | kept | yes (+ head `pub mod`) |
| `deprecated` | verifies in-flight only | **dropped** | kept | yes (VK-only) |
| `revoked` | no | dropped | **dropped** | **no** (manifest keeps the record) |

Rationale: bytecode is a *proving* artifact (a retired prover ships its own);
verification needs only the VK. So a superseded version keeps its VK to keep
verifying in-flight proofs, and a fully-obsolete one drops everything.

## Evolving a circuit

Editing the `.nr` sources does **not** change anything by itself — released
versions are frozen. Minting a new version is a deliberate step:

```sh
cargo xtask freeze-circuits          # the only step that runs nargo/bb and writes artifacts
cargo xtask freeze-circuits --check  # the dry run: every active artifact must reproduce
```

For each circuit whose ACIR or ABI changed it mints a new frozen version:

- **unchanged ACIR and ABI** → skipped (the freeze detects true ACIR equivalence — even a
  source edit that the noir optimizer removes is a no-op here).
- **changed ACIR, same ABI** → patch bump (e.g. `1.0.0 → 1.0.1`).
- **ABI changed** → pass `--abi-change` (minor) or `--semantic` (major + a new
  `DOMAIN` decision) to make the public-input-layout change explicit.

On a supersede it sets the previous version `deprecated`, then a reconcile pass
enforces the storage policy above (preserving `circuit_hash` before any deletion).
The new artifacts + manifest land in a **PR** — that review is the audit gate for
admitting a circuit. Status transitions (active → deprecated → revoked) are edits
to `manifest.toml`; the next `freeze-circuits` reconciles the on-disk artifacts.

Example — bumping the paynote circuit:

```
$ cargo xtask freeze-circuits
  unchanged  emit_mint @ 1.5.0
  minted     paynote 1.2.0 -> 1.2.1  (old -> deprecated)
  ...
# manifest: paynote v1.2.0 deprecated (+circuit_hash), v1.2.1 active
# resources: paynote/1.2.0/ -> circuit.vk only;  paynote/1.2.1/ -> bytecode+abi+vk
# CIRCUIT_REGISTRY: both paynote entries;  pub mod paynote -> v1.2.1
```

### `--check`

`--check` is the same compile and the same key derivation, asserted against the
committed `active` artifacts and writing nothing outside `target/`. It asserts
the `mise.toml` tool pins first — a key that reproduces under an unpinned `bb`
proves nothing — compiles a scratch copy of the whole `noir/` tree, and reports
every failing module before exiting 1. The `l1-freeze-check` CI job runs it and
then `git diff --exit-code`, which is what proves the dry run wrote nothing.

## Publishability

This crate stays acir-free (no git/noir deps) and ships to crates.io — `nargo`/`bb`
are invoked only by the `xtask` at freeze time, never on a normal build. The
committed frozen artifacts make `cargo build` deterministic with or without the
noir toolchain installed.
