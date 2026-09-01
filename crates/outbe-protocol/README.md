# outbe-protocol

[![crates.io](https://img.shields.io/crates/v/outbe-protocol.svg)](https://crates.io/crates/outbe-protocol)
[![release](https://img.shields.io/github/v/release/outbe/outbe-protocol.svg)](https://github.com/outbe/outbe-protocol/releases)
[![CI](https://github.com/outbe/outbe-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/outbe/outbe-protocol/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

**Single source of truth** for Outbe's entity, owner, payload, and wire-format
logic, written once against a swappable cryptographic [`Suite`].

A `Suite` selects the curve, field hash, signature scheme, KDF, and key
exchange. The production selection is **`OutbeV1`** (BN254 / Grumpkin,
Poseidon2, Grumpkin Schnorr).

## Architecture

The crate is four layers, bottom to top. Each layer only depends on the one
below it, so swapping a primitive never touches the protocol logic.

| Layer | Module | Responsibility |
| ----- | ------ | -------------- |
| **codec** | `codec` | `Codec` byte conventions + the `FieldElement` / `FieldEncode` encoding seam — how a typed value becomes one or more field elements. |
| **primitive** | `primitive::{curve, hash, signature, kdf, exchange}` | The swappable crypto traits and their instances: the embedded Grumpkin curve, the Poseidon2 field hash, Grumpkin Schnorr, the KDF, and the key-exchange "consent box". |
| **protocol** | `protocol::{entity, key, imt, zk, zkproof}` | Entity hashing, NFT keys/signers, the insertion Merkle tree, ZK backend seams, and canonical proof-wire marshaling. |
| **suite** | `suite` (+ `OutbeV1` at the crate root) | The `Suite` trait selects primitives and supplies `derive_owner`, `nft_hash`, and `signing_payload`. |

### What a `Suite` fixes

```rust
pub trait Suite: 'static {
    type Field: PrimeField;                                   // proving field — BN254 Fr
    type Curve: EmbeddedCurve<Base = Self::Field>;            // signature curve — Grumpkin
    type Hash: FieldHasher<Self::Field>;                      // field hash — Poseidon2
    type Signature: SignatureScheme<Field = Self::Field, ..>; // Grumpkin Schnorr
    type Kdf: Kdf<Self::Field>;
    type Exchange: KeyExchange<Self::Field>;                  // consent box

    // Formulas — default methods; a suite overrides only what differs.
    fn derive_owner(pk: &Affine<Self::Curve>, nonce: Self::Field) -> Result<Self::Field, Error>;
    fn nft_hash(id: Self::Field, body: &[Self::Field]) -> Result<Self::Field, Error>;
    fn signing_payload(nft_hash: Self::Field, nonce: Self::Field, binding: Self::Field) -> Result<Self::Field, Error>;
}
```

### Identity vs submission context

`derive_owner` and entity hashes are stable identity formulas. Ownership-style
circuits accept an opaque public `binding_hash`; the runtime or application
that owns that circuit defines and validates its context formula. The generic
protocol crate only includes that field in `signing_payload` and does not impose
a second U256 encoding.

### The ZK boundary

Everything **except** the zero-knowledge backend lives on the `Suite`. This
crate defines the ZK trait seams (`protocol::zk`) and canonical verifier-wire
marshaling (`protocol::zkproof`), including strict Solidity ABI and public-input
decoders. Concrete circuits, witness projections, verification keys, and the
Barretenberg implementation remain downstream in `outbe-zk-canonical` and
`outbe-zk-backend`, avoiding dependency cycles and keeping circuit artifacts
out of the protocol core.

## Usage

```toml
[dependencies]
outbe-protocol = "0.8"
outbe-protocol-derive = "0.8"   # for #[derive(Entity)]
```

### Protocol formulas

```rust
use outbe_protocol::{OutbeV1, Suite};

// Associated functions on the suite (generic over S: Suite); each returns
// Result<S::Field, Error>. OutbeV1 is the production selection.
let owner   = OutbeV1::derive_owner(&pk, nonce)?;                  // H(pk.x, pk.y, nonce)
let binding = application_context_hash;                            // defined by the owning runtime
let payload = OutbeV1::signing_payload(nft_hash, nonce, binding)?; // binding is application-owned
```

### Entity hashing with `#[derive(Entity)]`

Annotate a typed (e.g. Solidity-mirroring) struct; the macro reads the canonical
hash preimage off per-field roles instead of a hand-built `Vec<Field>`. See
[`outbe-protocol-derive`](../outbe-protocol-derive) for the full role reference.

```rust
use outbe_protocol::{OutbeV1, protocol::entity::{Entity, Owned}};
use outbe_protocol_derive::Entity;
use alloy_primitives::{Address, B256, U256};   // needs the `alloy` feature

#[derive(Entity)]
struct SpendingUnit {
    #[outbe(id_seed)]              id: B256,
    #[outbe(body, owner, pos = 0)] derived_owner: B256,
    #[outbe(body, pos = 1)]        attester: Address,
    #[outbe(body, pos = 2)]        amount: U256,   // `[120, 120, 16]`-bit limbs
}

let su = SpendingUnit { /* … */ };
let hash  = Entity::<OutbeV1>::entity_hash(&su)?;  // id = H(id_seed, id_body…); hash = H(id, body…)
let owner = Owned::<OutbeV1>::owner(&su)?;          // the stored derivedOwner
```

### Signing an ownership statement

The secret key stays encapsulated inside the `Signer`; you get a public key and
signatures, never the raw scalar.

```rust
use outbe_protocol::{OutbeV1, Suite, protocol::key::{NftSigner, Signer}};

let signer  = Signer::<OutbeV1>::local(&mut rng)?;     // fresh NFT key (self-issuance)
let pk      = signer.public_key();
let owner   = OutbeV1::derive_owner(&pk, nonce)?;

let binding = application_context_hash; // defined and validated by the owning runtime
let payload = OutbeV1::signing_payload(nft_hash, nonce, binding)?;
let sig     = signer.sign(&mut rng, payload)?;       // Grumpkin Schnorr — satisfies the in-circuit verifier
```

### A custom suite

Implement `Suite` to swap any primitive. The formulas are default methods, so a
new suite typically only restates the associated types it changes:

```rust
struct MySuite;
impl Suite for MySuite {
    type Field = ark_bn254::Fr;
    type Curve = /* … */;
    type Hash  = /* … */;
    type Signature = /* … */;
    type Kdf = /* … */;
    type Exchange = /* … */;
    // derive_owner / nft_hash / signing_payload inherited as defaults.
}
```

The test-only `Mock` suite in `tests/suite_battery.rs` shows the full shape and
exercises the cross-suite pluggability.

## Verifying releases

Releases ship sigstore cosign signatures + SLSA build-provenance attestations for every published `.crate`. See [SECURITY.md](../../SECURITY.md) for the threat model and the copy-pasteable verify recipe.

Quick check:

```sh
TAG=v0.8.0
ARTIFACT=outbe-protocol-${TAG#v}.crate
gh release download "$TAG" --repo outbe/outbe-protocol \
  --pattern "$ARTIFACT" --pattern "$ARTIFACT.sig" --pattern "$ARTIFACT.pem"
cosign verify-blob \
  --certificate "$ARTIFACT.pem" --signature "$ARTIFACT.sig" \
  --certificate-identity-regexp \
    '^https://github\.com/outbe/outbe-protocol/\.github/workflows/ci\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ARTIFACT"
```

## License

[MIT](../../LICENSE) — same as `outbe-vdf` and `outbe-poseidon`.
