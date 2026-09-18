//! `#[derive(Entity)]` — give a typed NFT struct its
//! [`outbe_zk_core::entity::Entity`] impl from per-field
//! `#[outbe(...)]` roles, so the canonical hash
//! preimage is read off the struct definition instead of a hand-built
//! `Vec<Field>`.
//!
//! Each named field declares one or more roles:
//!
//! - `#[outbe(id)]`   — exactly one field; it *is* the entity id, and the
//!   seed the body folds onto. Must encode to a single element (`FieldElement`).
//! - `#[outbe(body)]`    — the entity body, folded from the id.
//!
//! A `body` field of type `Vec<T>` is hashed as a canonical
//! **set**: it folds as `[ len, e₀, e₁, … ]` with the elements strictly
//! ascending by field value (see
//! [`outbe_zk_core::codec::SortedSet`]). The element `T` must be a
//! single [`outbe_zk_core::codec::FieldElement`], and the caller must supply the
//! vector already sorted + de-duplicated (an out-of-order or duplicate entry
//! is rejected at hash time with `Error::UnsortedSet`). The length prefix
//! removes the adjacent-vector boundary collision, and the strict ordering
//! makes the hash independent of the producer's vector order.
//! - `#[outbe(skip)]`    — explicitly excluded from the hash preimage.
//! - `#[outbe(pos = N)]` — explicit fold position within the `body` group.
//!   When present, the group is sorted by `N` instead of following
//!   declaration order — so a struct mirroring a `sol!` layout can fold its
//!   fields in the protocol's canonical order regardless of how the fields
//!   are declared. `pos` is all-or-nothing for the group, and positions
//!   must be unique.
//! - `#[outbe(limbed)]` — mark a *scalar* field as **limbed**: it folds through
//!   [`outbe_zk_core::codec::FieldEncode`] to the multiple field elements its type
//!   needs (e.g. a `uint256` → three `[120, 120, 16]`-bit limbs). Without `limbed` a scalar is
//!   **single** — it folds to exactly one [`outbe_zk_core::codec::FieldElement`] (the
//!   safe default; a wide type used without `limbed` has no `FieldElement`
//!   impl and fails to build). The limb *count* is a property of the type, so
//!   the flag carries intent only, not a number. `limbed` is rejected on a
//!   `Vec<T>` field (already a set of single-element items).
//!
//! Every field must carry one of the roles `id`, `body` or `skip`: a consensus
//! preimage must not silently omit a field. A field with no `#[outbe(...)]`
//! attribute, or one that names only `pos` / `limbed`, is a compile error. The
//! struct must have named fields and no generic parameters.
//!
//! The macro's real user is `TributeDraftClaim` in `outbe-l2-claims`
//! (`crates/outbe-l2-claims/src/claims/tribute.rs`). A smaller struct,
//! showing every role at once:
//!
//! ```ignore
//! #[derive(Entity)]
//! struct DemoClaim {
//!     #[outbe(id)]                    id: B256,          // must be < FR_MODULUS
//!     #[outbe(body, pos = 0)]         owner: B256,
//!     #[outbe(body, pos = 1)]         issuer: Address,
//!     #[outbe(body, limbed, pos = 2)] amount: U256,      // three canonical limbs
//!     #[outbe(body, pos = 3)]         su_ids: Vec<B256>, // canonical set: sorted, de-duplicated
//!     #[outbe(skip)]                  cached_hash: B256, // not in the preimage
//! }
//! ```
//!
//! The types come from `alloy-primitives` and need `outbe-zk-core`'s `alloy`
//! feature: `Address` and `B256` are single `FieldElement`s, while `U256` has
//! only a `FieldEncode` impl, which is why it needs `limbed`.

use proc_macro::TokenStream;
use quote::quote;
use syn::{spanned::Spanned, Data, DeriveInput, Fields, Ident, Type};

#[proc_macro_derive(Entity, attributes(outbe))]
pub fn derive_entity(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    expand(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[derive(Default)]
struct Roles {
    id: bool,
    body: bool,
    skip: bool,
}

struct FieldCfg {
    roles: Roles,
    pos: Option<u64>,
    /// `#[outbe(limbed)]`: a scalar field folds through `FieldEncode` to the
    /// multiple elements its type needs, instead of the single-element default.
    limbed: bool,
}

fn parse_field_cfg(field: &syn::Field) -> syn::Result<FieldCfg> {
    let mut roles = Roles::default();
    let mut pos = None;
    let mut limbed = false;
    for attr in &field.attrs {
        if !attr.path().is_ident("outbe") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            let id = meta
                .path
                .get_ident()
                .ok_or_else(|| meta.error("expected a bare role ident"))?
                .to_string();
            match id.as_str() {
                "id" => roles.id = true,
                "body" => roles.body = true,
                "skip" => roles.skip = true,
                "limbed" => limbed = true,
                "pos" => {
                    let lit: syn::LitInt = meta.value()?.parse()?;
                    pos = Some(lit.base10_parse()?);
                }
                other => {
                    return Err(meta.error(format!(
                        "unknown outbe key `{other}` (expected id, body, skip, limbed, or pos = N)"
                    )))
                }
            }
            Ok(())
        })?;
    }
    if !(roles.id || roles.body || roles.skip) {
        return Err(syn::Error::new(
            field.span(),
            "every field must carry a `#[outbe(...)]` role: `id`, `body` or `skip` (`pos` and `limbed` only modify one; use `#[outbe(skip)]` to exclude the field from the hash)",
        ));
    }
    Ok(FieldCfg { roles, pos, limbed })
}

/// Resolve a fold group's order: declaration order when no field sets
/// `pos`, otherwise sorted by `pos` (all-or-nothing, positions unique).
/// Each entry carries an opaque payload (the field's type + its `limbed`
/// flag) so emission can pick the right per-field encoding.
fn order_group<P>(
    fields: Vec<(Option<u64>, Ident, P)>,
    what: &str,
) -> syn::Result<Vec<(Ident, P)>> {
    if fields.iter().all(|(p, _, _)| p.is_none()) {
        return Ok(fields.into_iter().map(|(_, i, p)| (i, p)).collect());
    }
    if let Some((_, ident, _)) = fields.iter().find(|(p, _, _)| p.is_none()) {
        return Err(syn::Error::new(
            ident.span(),
            format!("`{ident}` has no `pos`, but another `{what}` field does; set `pos` on every `{what}` field or none"),
        ));
    }
    let mut fields = fields;
    fields.sort_by_key(|(p, _, _)| p.unwrap());
    for w in fields.windows(2) {
        if w[0].0 == w[1].0 {
            return Err(syn::Error::new(
                w[1].1.span(),
                format!(
                    "duplicate `pos = {}` among `{what}` fields",
                    w[1].0.unwrap()
                ),
            ));
        }
    }
    Ok(fields.into_iter().map(|(_, i, p)| (i, p)).collect())
}

/// If `ty` is `Vec<T>` (or `std::vec::Vec<T>`), return its element type `T`.
/// A `Vec` body field is hashed as a canonical *set* (length-prefixed,
/// strictly ascending) via [`outbe_zk_core::codec::SortedSet`] rather
/// than the ambiguous bare-slice concatenation.
fn vec_elem(ty: &Type) -> Option<Type> {
    let Type::Path(tp) = ty else { return None };
    let seg = tp.path.segments.last()?;
    if seg.ident != "Vec" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    args.args.iter().find_map(|a| match a {
        syn::GenericArgument::Type(t) => Some(t.clone()),
        _ => None,
    })
}

/// Emit the per-field encode call for a body field:
/// - `Vec<T>`              → the canonical sorted-set `FieldEncode` (via `SortedSet`);
/// - scalar + `limbed`     → the variable-width `FieldEncode` (its type's limbs);
/// - scalar (default)      → a single `FieldElement` (exactly one element).
fn emit_encode(ident: &Ident, ty: &Type, limbed: bool) -> proc_macro2::TokenStream {
    if vec_elem(ty).is_some() {
        quote! { ::outbe_zk_core::codec::FieldEncode::encode(&::outbe_zk_core::codec::SortedSet(&self.#ident), out)?; }
    } else if limbed {
        quote! { ::outbe_zk_core::codec::FieldEncode::encode(&self.#ident, out)?; }
    } else {
        quote! { out.push(::outbe_zk_core::codec::FieldElement::to_field(&self.#ident)?); }
    }
}

fn expand(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            input.generics.span(),
            "#[derive(Entity)] requires a struct with named fields and no generic parameters",
        ));
    }
    let name = &input.ident;
    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(n) => &n.named,
            _ => {
                return Err(syn::Error::new(
                    input.span(),
                    "#[derive(Entity)] requires a struct with named fields",
                ))
            }
        },
        _ => {
            return Err(syn::Error::new(
                input.span(),
                "#[derive(Entity)] can only be derived for structs",
            ))
        }
    };

    let mut seed: Option<(Ident, Type)> = None;
    // Payload per body field: its type + whether it is `limbed`.
    let mut body: Vec<(Option<u64>, Ident, (Type, bool))> = Vec::new();

    for f in fields {
        let ident = f.ident.clone().unwrap();
        let ty = f.ty.clone();
        let FieldCfg { roles, pos, limbed } = parse_field_cfg(f)?;
        if roles.skip {
            continue;
        }
        if limbed && vec_elem(&ty).is_some() {
            return Err(syn::Error::new(
                ident.span(),
                "`limbed` applies to scalar fields; a `Vec<T>` field is a set of single-element items",
            ));
        }
        if roles.id {
            if seed.is_some() {
                return Err(syn::Error::new(ident.span(), "duplicate `#[outbe(id)]`"));
            }
            seed = Some((ident.clone(), ty.clone()));
        }
        if roles.body {
            body.push((pos, ident.clone(), (ty.clone(), limbed)));
        }
    }

    let (seed_ident, seed_ty) = seed.ok_or_else(|| {
        syn::Error::new(
            name.span(),
            "an entity needs exactly one `#[outbe(id)]` field",
        )
    })?;
    let body = order_group(body, "body")?;

    // Dedup where-clause predicates by their textual form.
    let mut seen = std::collections::HashSet::new();
    let mut predicates: Vec<proc_macro2::TokenStream> = Vec::new();
    let mut push_pred = |ty: &Type, single: bool| {
        let key = (single, quote!(#ty).to_string());
        if seen.insert(key) {
            predicates.push(if single {
                quote!(#ty: ::outbe_zk_core::codec::FieldElement)
            } else {
                quote!(#ty: ::outbe_zk_core::codec::FieldEncode)
            });
        }
    };
    // The id seed is a single element.
    push_pred(&seed_ty, true);
    // Each body field's bound mirrors its encoding: a `Vec<T>` folds as a
    // sorted set, so its *element* must be a single `FieldElement`; a
    // `limbed` scalar folds through `FieldEncode` (its type's natural width);
    // a plain scalar is a single `FieldElement` (the default).
    for (_, (ty, limbed)) in body.iter() {
        match vec_elem(ty) {
            Some(elem) => push_pred(&elem, true),
            None => push_pred(ty, !*limbed),
        }
    }

    let body_encode = body.iter().map(|(i, (t, l))| emit_encode(i, t, *l));

    let entity_impl = quote! {
        impl ::outbe_zk_core::entity::Entity for #name
        where #(#predicates),*
        {
            fn id(&self) -> ::core::result::Result<::outbe_zk_core::Fr, ::outbe_zk_core::error::Error> {
                <#seed_ty as ::outbe_zk_core::codec::FieldElement>::to_field(&self.#seed_ident)
            }
            fn encode_body(&self, out: &mut ::std::vec::Vec<::outbe_zk_core::Fr>)
                -> ::core::result::Result<(), ::outbe_zk_core::error::Error>
            {
                #( #body_encode )*
                ::core::result::Result::Ok(())
            }
        }
    };

    Ok(entity_impl)
}
