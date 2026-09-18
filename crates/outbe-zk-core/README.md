# outbe-zk-core

The concrete cryptographic core of the Outbe zk circuits: **BN254** as the
proving field, **Grumpkin** as its embedded curve, **Poseidon2** as the hash and
**Grumpkin Schnorr** (BLAKE2s challenge) as the signature. Every formula is a
plain function over `ark_bn254::Fr`, re-exported as `outbe_zk_core::Fr`.
The crate is `#![forbid(unsafe_code)]`
and hashing routes through [`outbe-poseidon`](https://github.com/outbe/outbe-poseidon)
(git dependency, tag `v0.11.0`).

`outbe-zk-canonical`, `outbe-l2-claims`, `outbe-l2-zk-canonical` and
`outbe-zk-backend` all depend on this crate; it depends on none of them.

A change to a formula here does **not** move the frozen artifacts. The L1
bytecode and VKs under `outbe-zk-canonical/resources/circuits/` and the L2 keys
under `outbe-l2-zk-canonical/l2/` are derived from `.nr` sources by
`cargo xtask`, which never reads this crate; `xtask`'s manifest depends on no
workspace member at all. What a formula change does move is every value Rust
computes — the hash mirrors in `outbe-zk-canonical`, the entity and binding
hashes `outbe-l2-claims` folds for its claims, the witnesses the demo
builds. So a
change made here and not also made in the `.nr` sources surfaces as proofs that
stop verifying against unchanged keys, not as a rebuilt artifact. Changing a
protocol formula means editing both sides and re-freezing.

## Modules

### `codec` — typed values ↔ field elements ↔ bytes

Two traits: `FieldElement` (a value that *is* one field element, both ways) and
`FieldEncode` (a value that pushes one or more elements into a preimage).

- **Canonical vs. reducing decode.** `field_from_be_bytes` reduces modulo the
  field. `field_from_be_bytes_canonical` parses the bytes into the field's
  big-integer representation and rejects anything that is not already a field
  element with `Error::NonCanonical`, instead of silently reducing it.
  `FR_MODULUS` is exported as a public `[u8; 32]` for producers that want the
  bound itself; the decoder does not read it. The claim crates rely on
  that rejection: an id or an owner that does not fit the field is an error, not
  a different id. `fits_in_fr` is the same test as a predicate — it returns
  `bool`, it does not reject anything.
- **`U256`** crosses as three canonical `[120, 120, 16]`-bit limbs —
  `u256_limbs_be` / `u256_from_limbs_be`, and `fields_from_u256` /
  `fields_to_u256` under the `alloy` feature — the same representation Noir's
  bignum uses.
- **`SortedSet`** is the canonical set encoding: a length prefix followed by the
  elements, strictly ascending by field value. `sort_set` prepares a vector;
  an out-of-order or duplicate element is rejected at hash time with
  `Error::UnsortedSet`. The prefix is what keeps two adjacent set-valued fields
  from flattening ambiguously.
- Byte helpers: `field_to_be_bytes` and `field_from_be_bytes`, plus `field_from_b256`
  / `field_to_b256` under the `alloy` feature.

### `hash` — Poseidon2 and the protocol formulas

`poseidon2`, `iterate` (the rolling fold), `derive_owner` (the owner commitment
over a public key and a nonce), `nft_hash` (`iterate` seeded by an entity id),
`signing_payload` and `ascii_field` (a short ASCII string as one field element,
for domain separators).

### `imt` — the append-only inclusion tree

`Imt` with `new` / `append` / `root` / `depth` / `next_index` / `leaves` /
`inclusion_path` / `empty_inclusion_path`, the static helpers `node_hash`,
`empty_roots`, `empty_root` and `root_from_inclusion_path`, and `InclusionPath`
with `depth`, `root` and `circuit_indices`. Depth, domain and
empty leaf are the caller's — this module fixes none of them.

### `keys` — Grumpkin Schnorr and NFT key encapsulation

`keypair` / `public_key` / `sign` / `verify` over `PublicKey = ark_grumpkin::Affine`
and `Scalar = ark_grumpkin::Fr`, plus `coords` and `pedersen_hash3`. The wrappers
keep secrets from leaking *by accident*, not from a caller that asks:
`SecretScalar` is a non-`Copy` newtype that wipes on drop (`Drop` +
`ZeroizeOnDrop`) and lends the scalar out by reference through `expose`;
`NftSecret` holds one and adds `public_key`; `OwnerSeed` is the public
`(pk, nonce)` pair with `derive_owner`; `Signer` pairs an `NftSecret` with an
`OwnerSeed`.

`Signer` is built by `local` (fresh key + nonce) or `from_secret` (existing key
bound to its nonce). Its full surface is seven items: those two constructors,
`public_key`, `owner_seed` and `sign`, which keep the secret inside and are all
a witness builder needs, plus two accessors that deliberately hand it back —
`secret()` borrows the `NftSecret`, `into_secret()` consumes the signer and
returns it (`tests/formulas.rs` uses `secret().public_key()`; the demo's
fixtures go the other way, `NftSecret::new(sk)` into `from_secret`).

What comes back is the encapsulated secret, not a raw `Scalar`: `NftSecret`'s
field is private and it publishes only `new` and `public_key`, so outside this
crate the scalar is reachable only through a `SecretScalar` a caller built
itself. Inside the crate, `SecretScalar::expose` lends `&Scalar` to the curve
arithmetic. The contract a caller upholds is the one `SecretScalar` cannot
enforce: read the scalar by reference, never copy it out into a value that
outlives the wiping one — and note that the transient copies made by the
arithmetic consuming `expose()` live until their stack frames are reused.

### `shielded_pool` — shared purpose tags

`ShieldedPool::tag(domain, base)` folds a base purpose tag (`tag_note_sn`,
`tag_commitment`, `tag_nullifier`, `tag_change_key`, `tag_empty`) with a circuit's
own domain, so no two domains collide on the same purpose. `hash_multi(tag, values)`
absorbs the tag, the arity and then the values.

### `entity` — the `Entity` trait, and nothing else

`id()`, `encode_body()`, and the provided `entity_hash()` that folds the two
through `nft_hash`. Concrete entity types live in the claim crates. The
`#[outbe(...)]` field roles that generate an impl belong to
[`outbe-zk-core-derive`](../outbe-zk-core-derive); this crate re-exports the macro
as `outbe_zk_core::Entity`, so a consumer needs one dependency.

### `zk` — the backend seams

`Circuit` (a witness type, a public-input type, and the two flattenings
`public_inputs` / `witness_inputs`), `CircuitId` (the content-derived identity
consts `LABEL` / `VERSION` / `CIRCUIT_HASH` / `BYTECODE_B64` / `VK_BYTES` /
`VK_HASH`), and `ProofGenerator` / `ProofVerifier`. Concrete circuits and keys
live in `outbe-zk-canonical` and `outbe-l2-zk-canonical` (with the claim
contract in `outbe-l2-claims`); the proving backend is
`outbe-zk-backend`.

### `zkproof` — verifier-wire decoding

`decode_verify_call`, `decode_public_words::<N>`, `read_u64_be_padded` and
`ProofMarshalingError`. `decode_verify_call` and
`decode_public_words` return `Result<_, ProofMarshalingError>`, not
`Result<_, Error>` (`read_u64_be_padded` returns `Option`): a
non-canonical word is `ProofMarshalingError::NonCanonicalPublicInput(index)`,
which names the offending index, and the other variants name a length or count
mismatch. The `From<ProofMarshalingError> for Error` impl is what turns those
into the crate's own enum — that one variant into `Error::NonCanonical("public input")`, every
other into `Error::Proof(..)` — so `Error::NonCanonical` is the form seen after
a downstream decoder has converted, not what `decode_public_words` itself
returns. Circuit-specific combined-proof layouts live downstream.

### `error`

One `Error` enum for the crate: `Hash`, `Identity`, `OwnerMismatch`,
`NonCanonical`, `UnsortedSet`, `Proof`, `Merkle`.

## Features

`alloy` (off by default) adds two things. First, `FieldElement` / `FieldEncode`
impls for `Address`, `FixedBytes<32>`, `U16`/`U32`/`U64` and `FieldEncode` for
`U256`; they live here rather than in a consumer crate because of the orphan
rule. `U256` deliberately has no `FieldElement` impl, so it cannot seed an
entity id or stand in for an owner. Second, five `codec` functions that take or
return alloy types and do not exist without the feature: `fits_in_fr`,
`field_from_b256`, `field_to_b256`, `fields_from_u256` and `fields_to_u256`.

## Tests

`tests/codec.rs`, `tests/formulas.rs`, `tests/limbed.rs` and `tests/sorted_set.rs`
cover the fold vectors, limb widths and set ordering. They need no Noir toolchain
and no network.

## License

[MIT](../../LICENSE).
