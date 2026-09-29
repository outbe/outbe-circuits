# outbe-protocol

[![crates.io](https://img.shields.io/crates/v/outbe-protocol.svg)](https://crates.io/crates/outbe-protocol)
[![release](https://img.shields.io/github/v/release/outbe/outbe-protocol.svg)](https://github.com/outbe/outbe-protocol/releases)
[![CI](https://github.com/outbe/outbe-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/outbe/outbe-protocol/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

**Single source of truth** for Outbe's entity, owner, payload, and wire-format
logic over BN254 / Grumpkin, Poseidon2, and Grumpkin Schnorr.

`Fr` is re-exported from the crate root. Cryptographic types are concrete;
entity, signer, circuit, and backend traits describe application interfaces
rather than selectable cryptographic suites.

## Architecture

The existing module paths separate encoding, concrete primitives, and protocol
operations:

| Layer | Module | Responsibility |
| ----- | ------ | -------------- |
| **codec** | `codec` | Canonical byte functions and the `FieldElement` / `FieldEncode` traits — how a typed value becomes one or more BN254 field elements. |
| **primitive** | `primitive::{curve, hash, signature, kdf, exchange}` | Concrete Grumpkin operations, Poseidon2 hash formulas, Schnorr signatures, KDF, and ECDH consent box. |
| **protocol** | `protocol::{entity, key, imt, zk}` | Entity hashing, NFT keys/signers, the insertion Merkle tree, and circuit/prover/verifier interfaces. |


### Identity vs submission context

`primitive::hash::BINDING_DOMAIN` remains `1` and is folded into `binding` —
and therefore into each signed submission. It is deliberately not folded into
`derive_owner` or the entity hashes. The concrete-API refactor changes neither
these preimages nor any frozen circuit, verification key, or proof layout.

### The ZK boundary

This crate defines the ZK trait seams and core proof types (`protocol::zk`) plus
generic verifier-envelope and combined-proof validation (`protocol::zkproof`).
Concrete witness projections, circuit-specific public-input decoders, and
verification keys live in `outbe-zk-canonical`; ACVM witness solving and
Barretenberg proving/verifying live in `outbe-zk-backend`. This keeps concrete
circuit implementations out of the protocol core without duplicating common
wire validation.

## Usage

```toml
[dependencies]
outbe-protocol = "0.8"
outbe-protocol-derive = "0.8"   # for #[derive(Entity)]
```

### Protocol formulas

```rust
use outbe_protocol::primitive::hash;

let owner   = hash::derive_owner(&pk, nonce)?;
let binding = hash::binding(&sender, &commitment_id, host_chain_id, l2_chain_id)?;
let payload = hash::signing_payload(nft_hash, nonce, binding)?;
// sender: &[u8; 20]   commitment_id: &[u8; 32]   host_chain_id, l2_chain_id: u64
```

`binding` hashes `[BINDING_DOMAIN, sender, cid_lo128, cid_hi128, host_chain_id, l2_chain_id]`,
with the commitment ID's low 128-bit limb first. The verifier recomputes it from
the caller, commitment ID, its own host chain, and the selected L2. The L2 chain
ID is required: this six-input formula replaces the former five-input formula,
even when `l2_chain_id` is zero. Provers and verifiers must migrate together.
The circuits consume the resulting hash as an opaque public input, so their
verification keys do not change.

### Converting field values

`FieldElement::from_field` reverses single-field encoding and rejects values
outside the target type's range. Custom `FieldElement` implementations must
provide both `to_field` and `from_field`.

```rust
use outbe_protocol::{FieldElement, Fr};

let field: Fr = 42u64.to_field()?;
let value = u64::from_field(&field)?;
// With the alloy feature: B256::from_field(&field), Address::from_field(&field).
```

With the `alloy` feature, `codec::fields_from_u256` and `codec::fields_to_u256`
convert full-width amounts using the same three `[120, 120, 16]`-bit limbs as
`FieldEncode` and `u256_limbs_be`. `B256` remains the type for a single field word.
Key codec functions also live in `codec`; compressed public/secret keys use
32-byte arrays and preserve the existing arkworks compressed encoding.

### Entity hashing with `#[derive(Entity)]`

Annotate a typed (e.g. Solidity-mirroring) struct; the macro reads the canonical
hash preimage off per-field roles instead of a hand-built `Vec<Field>`. See
[`outbe-protocol-derive`](../outbe-protocol-derive) for the full role reference.

```rust
use outbe_protocol::protocol::entity::{Entity, Owned};
use outbe_protocol_derive::Entity;
use alloy_primitives::{Address, B256, U256};   // needs the `alloy` feature

#[derive(Entity)]
struct SpendingUnit {
    #[outbe(id_seed)]              id: B256,
    #[outbe(body, owner, pos = 0)] derived_owner: B256,
    #[outbe(body, pos = 1)]        attester: Address,
    #[outbe(body, limbed, pos = 2)] amount: U256,   // `[120, 120, 16]`-bit limbs
}

let su = SpendingUnit {
    id: B256::ZERO,
    derived_owner: B256::ZERO,
    attester: Address::ZERO,
    amount: U256::from(100),
};
let hash = su.entity_hash()?;  // id = H(id_seed, id_body…); hash = H(id, body…)
let owner = su.owner()?;      // the stored derivedOwner
```

### Signing an ownership statement

The secret key stays encapsulated inside the `Signer`; you get a public key and
signatures, never the raw scalar.

```rust
use outbe_protocol::{primitive::hash, protocol::key::{NftSigner, Signer}};

let signer = Signer::local(&mut rng)?;
let pk = signer.public_key();
let nonce = signer.owner_seed().nonce;
let owner = hash::derive_owner(&pk, nonce)?;

let binding = hash::binding(&[1u8; 20], &[2u8; 32], 7, 0xdead)?;
let payload = hash::signing_payload(nft_hash, nonce, binding)?;
let sig = signer.sign(&mut rng, payload)?; // Grumpkin Schnorr, verified in-circuit
```

### Remote signer issuance

The consent-box flow remains available with concrete Grumpkin keys:

```rust
use outbe_protocol::{primitive::exchange, protocol::key::Signer};

let (consent_sk, consent_pk) = exchange::random_keypair(&mut rng);
let (seed, opaque_pk) = Signer::issue_for_remote(&mut rng, &consent_pk)?;
let signer = Signer::from_exchange(&consent_sk, &opaque_pk, seed.nonce)?;
```

The server returns public artifacts only and wipes its ephemeral and derived
secrets. The recipient reconstructs the same NFT signing key through ECDH.

### Migrating callers

- Remove `Suite`, `CircuitSuite`, and `OutbeV1` imports and type arguments.
- Call `primitive::hash` functions for formulas and `codec` functions for byte
  conversions. Use `primitive::signature` and `primitive::exchange` for key operations.
- Use concrete `Signer`, `Entity`, `Owned`, `Imt`, `InclusionPath`, and
  `ShieldedPool` APIs; encoding traits no longer take a field parameter.
- Implement `Circuit`, `ProofGenerator<C>`, and `ProofVerifier<C>` without a
  suite parameter. The circuit type remains generic.
- Keep `id_seed` and `id_body` roles: the entity id is still folded before its
  body. Merkle `append` still returns the index and `Append` record, and the
  stateless frontier API is retained.

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
