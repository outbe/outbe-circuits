# outbe-zk-canonical

[![crates.io](https://img.shields.io/crates/v/outbe-zk-canonical.svg)](https://crates.io/crates/outbe-zk-canonical)
[![release](https://img.shields.io/github/v/release/outbe/outbe-circuits.svg)](https://github.com/outbe/outbe-circuits/releases)
[![CI](https://github.com/outbe/outbe-circuits/actions/workflows/ci.yml/badge.svg)](https://github.com/outbe/outbe-circuits/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Concrete canonical circuit, witness, and verifier-wire types for the Outbe
protocol (ownership, Demo Tribute, Emit mint, Paynote, and Niflheim Tribute),
built on the generic seams and marshaling helpers in `outbe-protocol`.
The `demo_tribute`, `emit_mint`, and `paynote` modules own their circuit-specific
combined-proof layouts and public-input decoders. This crate also holds the
**append-only L1 release registry** and **VK-pinned L2 chain-version selections**,
with stable or explicitly mutable package identities.

Alloy support is optional and disabled by default. Enable `features = ["alloy"]`
to use the Emit mint and Paynote `PublicInputs` and `decode_public_inputs` APIs
and their Alloy hash helpers. Decoders return `Address`, `B256`, and `U256`
values. Alloy hash helpers serialize addresses with `FieldElement` and amounts
with `codec::fields_from_u256`. The always-available `_raw` functions use
`[u8; 20]` addresses and field elements; `note_commitment_raw` accepts
`[Field; 3]` amount limbs. Hash helpers retain field elements
for serials, keys, and results. Byte/ABI limb conversions are available directly
in `outbe_protocol::codec::{u256_limbs_be, u256_from_limbs_be}`. Generated Noir
witness types retain their ABI layout, including three `[120, 120, 16]`-bit limbs for
each amount.

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
`leaf_index` is converted to little-endian path bits inside the Emit helper:
zero selects the current node as left; one selects it as right.

### Amount encoding (256-bit)

Amounts are `noir-bignum`'s `U256` — three little-endian limbs of radix 2^120
(`limbs[0..2] < 2^120`, `limbs[2] < 2^16`) — crossing the ABI as `[u128; 3]`.
Alloy `U256` conversions live in [`outbe_zk_canonical::u256`](src/u256.rs).
Two encoding rules are load-bearing:

- **Canonicality is enforced in-circuit.** The ABI carries raw `u128` limbs with
  no range check; `U256::validate_in_range` in `main` is the gate that makes the
  limb-wise ordering, subtraction, and hashing mean what they claim.
- **The commitment hashes limbs, not a folded field element.** A 256-bit amount
  does not fit the 254-bit proving field: folding would alias amounts differing
  by the field modulus. The preimage is
  `(chain_id, serial, limbs[0], limbs[1], limbs[2])`.

`EMIT_DOMAIN` is unchanged from 1.4.x: `hash_multi` seeds its state with the
preimage length, so the 3-element (u128-era) and 5-element (limb) preimages
cannot collide. Notes committed under 1.4.x are **not** provable under 1.5.0 —
the commitment formula changed — so the runtime must migrate note commitments
when it adopts 1.5.0.

The circuit does **not** select or authenticate the payout recipient and does not
mutate ledger state. The verifier/runtime must bind `chain_id`, accept the
supplied root, reject a previously consumed nullifier, record any change
commitment, and authorize and execute the payout.

## Paynote statement

`outbe.paynote@1.3.0` proves the right to spend part or all of a private ERC20
payment note committed under a public chain root, without revealing the note's
total value. The note is a **bearer instrument**: spend authority is knowledge of
`note_spend_key`. There is no committed owner identity and no spender allow-list.
`context` is an opaque public field the verifier binds to one settlement; the
circuit does not hash its preimage.

| Input | Meaning |
|---|---|
| `chain_id` | Chain containing the pool. |
| `root` | Accepted depth-32 note-commitment root. |
| `nullifier` | Deterministic identifier consumed to prevent a second spend. |
| `asset` | ERC20 token address the note is denominated in. |
| `context` | Non-zero public commitment to the settlement this spend authorizes. |
| `spend_amount` | Public 256-bit amount being spent from the private note. |
| `change_commitment` | Commitment to unspent value, or zero for a full spend. |

The private witness is the 256-bit `note_amount`, `note_spend_key`,
`leaf_index`, and `auth_path`. Amounts cross the ABI as noir-bignum `U256`
limbs (`[u128; 3]`, little-endian radix $2^{120}$); both public and private
limbs are constrained in-circuit to the canonical range $1..2^{256}-1$.
The circuit checks:

1. `asset` is an in-range (160-bit) nonzero address, and `context` is nonzero.
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

- **Require `context` to equal the settlement this call performs.** The circuit
  authenticates the field and rejects zero. It does not hash a preimage and
  does not bind an address, and the nullifier does not depend on `context`.
  A copied proof verifies only for the same public inputs, so a verifier that
  recomputes `context` from the operation rejects a substituted target. A
  verifier that ignores `context` accepts the proof for any operation with the
  same asset and amount. Anyone may submit the proof verbatim.
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

- Circuit-specific proving modules with `Witness` / `PublicInputs`, `Circuit` /
  `CircuitId` implementations, and frozen identity/codec constants. L1 modules
  describe the latest active release. L2 modules use the package's Nargo name;
  their descriptive `VERSION` is the latest registered chain version selecting
  that package, not an independent package release.
- `pub static CIRCUIT_REGISTRY` contains every non-revoked **L1** release once,
  with its version, lifecycle status, hashes, and verification key.
- Private L2 package descriptors are shared across chain-version selections.
  `outbe_zk_canonical::l2_circuits(chain_id, version)` returns references to their
  package paths, pinned VK hashes, and raw verification keys. There are no
  per-chain Rust modules or duplicate L2 declarations in the L1 catalog.

## Layout

```text
circuits/manifest.toml                      # L1 releases + L2 chain-version arrays
noir/<module>/                             # conventional L1 source packages
noir/outbe-circuit-core/                    # shared Noir library
resources/circuits/<module>/<version>/      # frozen L1 artifacts
l2/<chain_id>/<package>/                    # one L2 source/key package
    Nargo.toml
    src/main.nr
    abi.json
    bytecode.b64
    circuit.vk
    target/<nargo-name>.json                # compiler output, not the registry
```

`manifest.toml` declares the global `proof_system` and shared `libraries`.
Each L1 `[[circuit]]` has only `module`, `label`, and nested
`[[circuit.versions]]` records. Source and artifact paths follow the conventions
above; they are not repeated in the manifest.

```toml
[[circuit]]
module = "paynote"
label = "outbe.paynote"

[[circuit.versions]]
version = "1.2.0"
status = "active"
```

L1 release records retain `circuit_hash` after their bytecode is dropped.
Both `build.rs` and `xtask` use this catalog without another hardcoded circuit
list. Circuit-specific Rust paths remain, such as `noir::niflheim_tribute`.
Nargo package names must be unique among generated modules; versioned package
directories may use corresponding distinct names.

### L2 chain versions

A **chain version selects an array of packages**. It is not a circuit artifact
version, and a directory suffix does not determine it. Each `path` is relative
to `l2/<chain_id>/`; `tribute`, `tribute-1`, and `tribute-2` are valid names.
The package owns one flat set of frozen artifacts, without a nested release
history or a separate global circuit declaration.

```toml
[[l2_chain]]
chain_id = 9900501

[[l2_chain.versions]]
version = "1.0.0"
stable = true
circuits = [
  { path = "tribute", vk_hash = "7ec39936f08a1f5bb5675249be8c2ee3a31811a604e2785ab31b670eaaa2e7f9" },
]
```

Another `[[l2_chain.versions]]` under that chain can select a different array.
Shared package paths reuse the same descriptor and must agree on their pin.
The verifier selects an exact version; it does not silently accept the latest.

```rust
use outbe_zk_canonical::l2_circuits;

let circuits = l2_circuits(9_900_501, "1.0.0"); // &'static [&'static L2Circuit]
let tribute = circuits.iter().find(|entry| entry.path == "tribute");
let vk_bytes = tribute.map(|entry| entry.vk_bytes);
```

Lookup preserves the declared array order, allocates nothing, and returns an
empty slice for unknown chains or versions. Each descriptor exposes `path`,
`vk_hash`, and `vk_bytes`; there is no second hash lookup and no L1 lifecycle
status attached to an L2 package.

`vk_hash = keccak256(circuit.vk)` pins the actual verification identity. A normal
build checks the committed key against every pin. Tooling recompiles the source
with the pinned Noir/barretenberg versions and checks the resulting key too.
Duplicate chain IDs, duplicate versions, duplicate paths within a selection,
conflicting pins for a shared path, and paths escaping their chain are rejected.

- **Stable chain version:** the verification key cannot change in place.
  Comments, refactoring, and ABI field renames are allowed when the key stays
  identical. This is not a source-byte or ABI-name freeze.
- **Mutable chain version:** an explicit freeze can refresh its package
  artifacts and VK pin without changing the chain version.
- **Shared package:** any stable reference protects its key, even if another
  version referencing the same package is mutable.

Demo (`57005`, `0xdead`) is devnet/testnet-only: it stays on chain version
`1.0.0`, with `stable = false`, selecting [`l2/57005/tribute/`](l2/57005/tribute).
Its former independent artifact-release history is no longer a registry model.
Niflheim (`9900501`) uses stable chain version `1.0.0`, selecting
[`l2/9900501/tribute/`](l2/9900501/tribute) with its existing key unchanged.

## L1 lifecycle & storage policy

| status | accepts proofs? | bytecode + abi | vk | in `CIRCUIT_REGISTRY`? |
|---|---|---|---|---|
| `active` | yes | kept (provable) | kept | yes (+ head `pub mod`) |
| `deprecated` | verifies in-flight only | **dropped** | kept | yes (VK-only) |
| `revoked` | no | dropped | **dropped** | **no** (manifest keeps the record) |

Bytecode is a proving artifact: superseded L1 releases keep their VK for
verification while retired provers carry their own bytecode. L2 packages instead
follow their chain version's stability policy and retain flat proving artifacts.

## Evolving L1 circuits

Editing the `.nr` sources does **not** change anything by itself — released
versions are frozen. Minting a new version is a deliberate step:

```sh
cargo xtask freeze-circuits          # mint versions and write frozen artifacts
```

For each L1 circuit whose ACIR or ABI changed it mints a new frozen version:

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

## Evolving L2 packages

Use the same `cargo xtask freeze-circuits` command. It never invents or bumps
chain versions. For a mutable version it refreshes flat package artifacts and
the manifest pin. For a stable version it first requires the derived VK to match
the existing pin; unchanged-key ABI/bytecode updates may then be refreshed.
All L2 keys are validated before any L2 artifacts are replaced.

A stable key change requires a new package path and an explicitly added chain
version selecting it. Keep the old package for versions still referencing it.
Create the new package with its source and `Nargo.toml`, without copied frozen
artifacts. Its new manifest entry may initially omit `vk_hash`; normal freezing
derives the key, writes the flat artifacts, and fills the pin. Removing a pin
from an already-frozen stable package does not authorize changing its key.
Normal Cargo builds and read-only checks require completed pins.

## Read-only verification

For a read-only reproducibility check, run `cargo xtask freeze-circuits --check`
or `mise run freeze-circuits:check`. This requires the exact `nargo`/`bb` pins
from `mise.toml` and compiles the registered packages in a temporary tree under
`target/`. L1 checks compare decoded ACIR, structural ABI, and freshly derived VK.
L2 checks compare the committed and freshly derived VKs against each manifest
pin, regardless of `stable`; source spelling and ABI-only changes do not fail
when the VK is unchanged. The check never refreshes artifacts, updates pins,
bumps versions, or changes tracked compiler output. Scratch files are removed
on success or failure. CI uses this check.

## Publishability

This crate stays acir-free (no git/noir deps) and ships to crates.io — `nargo`/`bb`
are invoked by circuit tooling when freezing or checking, never on a normal build. The
committed frozen artifacts make `cargo build` deterministic with or without the
noir toolchain installed.
