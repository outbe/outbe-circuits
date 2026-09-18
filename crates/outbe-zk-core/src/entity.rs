//! Entity model — **trait only**.
//!
//! An entity is a declarative preimage: an *id* (the entity's identity, and
//! the seed the body folds onto) and an ordered *body*. An entity *encodes itself*: it
//! pushes its members — through [`crate::codec::FieldEncode`] — in
//! canonical order, so the named, typed structure of an NFT lives in the
//! type, not in an out-of-band filling convention.
//!
//! This core declares only the [`Entity`] trait. The concrete entity types
//! live in consumer crates, where `#[derive(Entity)]` generates the impl
//! from `#[outbe(...)]` field roles.

use crate::error::Error;
use crate::hash::nft_hash;
use crate::Fr;

/// A hashable entity.
///
/// An entity says *what* to hash and in *what* order; [`nft_hash`] does the
/// folding, so an entity never says *how*. The id seeds the accumulator and
/// `encode_body` supplies the body that folds onto it.
pub trait Entity {
    /// The entity's identity, and the seed the body folds onto. Fallible
    /// because the id may be a `bytes32` that must decode canonically.
    fn id(&self) -> Result<Fr, Error>;
    /// Append the entity body, folded from the id to produce the hash.
    fn encode_body(&self, out: &mut Vec<Fr>) -> Result<(), Error>;

    /// The canonical entity hash.
    fn entity_hash(&self) -> Result<Fr, Error> {
        let mut body = Vec::new();
        self.encode_body(&mut body)?;
        nft_hash(self.id()?, &body)
    }
}
