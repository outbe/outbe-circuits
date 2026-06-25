# outbe-protocol

[![crates.io](https://img.shields.io/crates/v/outbe-protocol.svg)](https://crates.io/crates/outbe-protocol)
[![release](https://img.shields.io/github/v/release/outbe/outbe-protocol.svg)](https://github.com/outbe/outbe-protocol/releases)
[![CI](https://github.com/outbe/outbe-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/outbe/outbe-protocol/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

**Single source of truth** for the Outbe consensus-binding protocol logic —
the entity/owner/binding/payload hash formulas, the ownership-proof
statement, and the witness/public-input semantics — written **once**
against a swappable cryptographic [`Suite`].

A `Suite` selects the curve, field hash, signature scheme, and KDF, and
supplies the protocol formulas as overridable defaults. The production
selection is **`OutbeV1`** (BN254 / Grumpkin, Poseidon2, Grumpkin Schnorr).
The same logic can be re-parameterised for a future suite (`OutbeV2`, …) without
rewriting the protocol — the `DOMAIN` constant keeps the versions from
colliding on the wire.

## Architecture

The crate is four layers, bottom to top. Each layer only depends on the one
below it, so swapping a primitive never touches the protocol logic.

| Layer | Module | Responsibility |
| ----- | ------ | -------------- |
| **codec** | `codec` | `Codec` byte conventions + the `FieldElement` / `FieldEncode` encoding seam — how a typed value becomes one or more field elements. |
| **primitive** | `primitive::{curve, hash, signature, kdf, exchange}` | The swappable crypto traits and their instances: the embedded Grumpkin curve, the Poseidon2 field hash, Grumpkin Schnorr, the KDF, and the key-exchange "consent box". |
| **protocol** | `protocol::{entity, key, imt, zk}` | The protocol logic — entity hashing, NFT keys/signers, the insertion Merkle tree, and the ZK trait seams — all generic over `S: Suite`. |
| **suite** | `suite` (+ `OutbeV1` at the crate root) | The `Suite` trait wires one choice per primitive and supplies `derive_owner` / `nft_hash` / `signing_payload` / `binding` as default methods. |

### What a `Suite` fixes

```rust
pub trait Suite: 'static {
    type Field: PrimeField;                                   // proving field — BN254 Fr
    type Curve: EmbeddedCurve<Base = Self::Field>;            // signature curve — Grumpkin
    type Hash: FieldHasher<Self::Field>;                      // field hash — Poseidon2
    type Signature: SignatureScheme<Field = Self::Field, ..>; // Grumpkin Schnorr
    type Kdf: Kdf<Self::Field>;
    type Exchange: KeyExchange<Self::Field>;                  // consent box
    const DOMAIN: u64 = 0;                                    // protocol-version tag (OutbeV1 = 1)

    // Formulas — default methods; a suite overrides only what differs.
    fn derive_owner(pk: &Affine<Self::Curve>, nonce: Self::Field) -> Result<Self::Field, Error>;
    fn nft_hash(id: Self::Field, body: &[Self::Field]) -> Result<Self::Field, Error>;
    fn signing_payload(nft_hash: Self::Field, nonce: Self::Field, binding: Self::Field) -> Result<Self::Field, Error>;
    fn binding(sender: &[u8; 20], commitment_id: &[u8; 32], chain_id: u64) -> Result<Self::Field, Error>;
}
```

### Identity vs submission

`DOMAIN` is folded into `binding` — and therefore into every signature
(`signing_payload`) and the aggregation public inputs — so the protocol version
is bound into the whole submission/proof path. It is deliberately **not** folded
into `derive_owner` or the entity hashes: an NFT keeps its identity across suite
versions, while a submission is unambiguously tied to one version.

### The ZK boundary

Everything **except** the zero-knowledge layer lives on the `Suite`. This crate
defines only the ZK trait seams — `Circuit`, `ProofGenerator`, `ProofVerifier`
(`protocol::zk`) — and the statement *semantics* (`derive_owner` /
`signing_payload` / `binding`). The concrete circuits, the witness/public-input
projection, the aggregation tier ladder, and the verification keys are keyed by
the suite but live downstream in `outbe-circuits-canonical`, so circuit-ABI
drift never reaches the protocol.

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
let owner   = OutbeV1::derive_owner(&pk, nonce)?;                   // H(pk.x, pk.y, nonce)
let binding = OutbeV1::binding(&sender, &commitment_id, chain_id)?; // H([DOMAIN, sender, cid_lo, cid_hi, chain])
let payload = OutbeV1::signing_payload(nft_hash, nonce, binding)?;  // the field the owner signs
//  sender: &[u8; 20]   commitment_id: &[u8; 32]   chain_id: u64
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
    #[outbe(body, pos = 2)]        amount: U256,   // a uint256 folds as [lo, hi]
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

let payload = OutbeV1::signing_payload(nft_hash, nonce, binding)?;
let sig     = signer.sign(&mut rng, payload)?;       // Grumpkin Schnorr — satisfies the in-circuit verifier
```

### A custom suite

Implement `Suite` to swap any primitive. The formulas are default methods, so a
new suite typically only restates the associated types it changes and bumps
`DOMAIN`:

```rust
struct MySuite;
impl Suite for MySuite {
    type Field = ark_bn254::Fr;
    type Curve = /* … */;
    type Hash  = /* … */;
    type Signature = /* … */;
    type Kdf = /* … */;
    type Exchange = /* … */;
    const DOMAIN: u64 = 2;
    // derive_owner / binding / signing_payload inherited as defaults.
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
