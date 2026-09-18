//! Grumpkin keys: the curve, the Schnorr scheme the circuits verify, and the
//! NFT key encapsulation.
//!
//! Grumpkin is BN254's *embedded* curve — its base field is the proving field
//! [`Fr`], so an affine point's coordinates are native field elements (no limb
//! decomposition, native in-circuit EC ops).
//!
//! A [`Signer`] is the one key primitive: it encapsulates the NFT secret and
//! offers the public [`OwnerSeed`] (the embedded public key + nonce that feed
//! `derivedOwner`) plus a signing operation, so a witness builder never holds
//! a key. It is encapsulation, not a one-way door — [`Signer::secret`] and
//! [`Signer::into_secret`] hand the [`NftSecret`] back, still wrapped in its
//! drop-wiping [`SecretScalar`]. Two constructors cover the real flows:
//!
//! - [`Signer::local`] — local self-issuance: fresh key + nonce generated
//!   internally (e.g. a Tribute Draft).
//! - [`Signer::from_secret`] — bind an existing NFT key to the nonce its
//!   `derivedOwner` commits to.

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_std::rand::Rng;
use ark_std::UniformRand;
use blake2::{Blake2s256, Digest};
use zeroize::Zeroize;

use crate::error::Error;
use crate::Fr;

// ----------------------------------------------------------------------
// The curve.
// ----------------------------------------------------------------------

/// An affine Grumpkin point — the shape of a public key. Its coordinates are
/// native [`Fr`] elements (`ark_grumpkin::Fq == ark_bn254::Fr`).
pub type PublicKey = ark_grumpkin::Affine;

/// Grumpkin's scalar field — the shape of a secret key. Deliberately **not**
/// [`Fr`]: this is the curve's group order (`ark_bn254::Fq`), a different
/// field from the proving field.
pub type Scalar = ark_grumpkin::Fr;

/// Affine `(x, y)` as native field elements, rejecting the identity.
pub fn coords(p: &PublicKey) -> Result<(Fr, Fr), Error> {
    let (x, y) = p.xy().ok_or(Error::Identity("curve point coords"))?;
    Ok((x, y))
}

/// `[scalar]·G`.
fn mul_generator(scalar: &Scalar) -> ark_grumpkin::Projective {
    ark_grumpkin::Projective::generator().mul_bigint(scalar.into_bigint())
}

/// Reinterpret a base-field element as a scalar (canonical for the
/// BN254/Grumpkin cycle: `r < q`, so the reduction is a no-op and the
/// map is injective). Used to turn a Pedersen input into a scalar.
fn base_to_scalar(x: &Fr) -> Scalar {
    Scalar::from_le_bytes_mod_order(&x.into_bigint().to_bytes_le())
}

// ----------------------------------------------------------------------
// Schnorr over Grumpkin — the scheme the Outbe circuits verify.
// ----------------------------------------------------------------------
//
// Keys are on Grumpkin: secret `sk ∈ Scalar`, public `pk = sk·G`. A signature
// is `s ‖ e` (each a 32-byte big-endian value). The challenge is
// `e = blake2s( pedersen_hash3(R.x, pk.x, pk.y).to_be_bytes() ‖ message )`,
// and `s = k − e·sk` for the per-signature nonce `R = k·G`. Verification
// recomputes `R' = s·G + e·pk` and checks the challenge reproduces `e`.
//
// ## Nonce derivation
//
// `k` is derived **deterministically** from `(sk, message)` (RFC 6979–style:
// `k = blake2s(domain ‖ sk ‖ aux ‖ counter ‖ message)`), *not* drawn straight
// from the RNG. A reused or biased `k` for two different messages under one
// key leaks `sk`; binding `k` to `(sk, message)` makes that impossible
// regardless of RNG quality — the decisive property for on-device signing.
// The caller's RNG is folded in only as auxiliary entropy (`aux`), a hedge
// that adds fault-attack resistance when the RNG is good but that safety
// never depends on (a broken or constant RNG still yields a
// per-message-unique `k`). `counter` is bumped only for the rare retry when
// `k`/`e`/`s` is zero.

/// Domain tag for the deterministic nonce hash, kept distinct from the
/// challenge hash so the two blake2s invocations can never collide.
const NONCE_DOMAIN: &[u8] = b"outbe/schnorr/nonce/v1";

/// 32-byte big-endian encoding of a 256-bit field element.
fn field_to_be32<F: PrimeField>(f: &F) -> [u8; 32] {
    f.into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("256-bit field")
}

/// Decode a 64-char big-endian hex string into a Grumpkin coordinate.
fn grumpkin_fq_from_hex(hex: &str) -> ark_grumpkin::Fq {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    assert_eq!(hex.len(), 64, "expected 32-byte hex");
    let mut bytes = [0u8; 32];
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    for (byte, pair) in bytes.iter_mut().zip(pairs) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).expect("ascii hex"), 16)
            .expect("hex digit");
    }
    ark_grumpkin::Fq::from_be_bytes_mod_order(&bytes)
}

/// Grumpkin's Pedersen generators — `[G0, G1, G2, length_generator]`, the
/// committed constants the noir circuits use. Consensus constants.
fn pedersen_generators() -> [PublicKey; 4] {
    let pt = |x: &str, y: &str| {
        ark_grumpkin::Affine::new_unchecked(grumpkin_fq_from_hex(x), grumpkin_fq_from_hex(y))
    };
    [
        pt(
            "0x083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a",
            "0x1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d",
        ),
        pt(
            "0x054aa86a73cb8a34525e5bbed6e43ba1198e860f5f3950268f71df4591bde402",
            "0x209dcfbf2cfb57f9f6046f44d71ac6faf87254afc7407c04eb621a6287cac126",
        ),
        pt(
            "0x1c44f2a5207c81c28a8321a5815ce8b1311024bbed131819bbdaf5a2ada84748",
            "0x03aaee36e6422a1d0191632ac6599ae9eba5ac2c17a8c920aa3caf8b89c5f8a8",
        ),
        pt(
            "0x2df8b940e5890e4e1377e05373fae69a1d754f6935e6a780b666947431f2cdcd",
            "0x2ecd88d15967bc53b885912e0d16866154acb6aac2d3f85e27ca7eefb2c19083",
        ),
    ]
}

/// `pedersen_hash([a, b, c]) = (G0·a + G1·b + G2·c + L·3).x`, scalars taken
/// as the integer values of the inputs.
pub fn pedersen_hash3(a: Fr, b: Fr, c: Fr) -> Result<Fr, Error> {
    let [g0, g1, g2, l] = pedersen_generators();
    let acc = g0.mul_bigint(base_to_scalar(&a).into_bigint())
        + g1.mul_bigint(base_to_scalar(&b).into_bigint())
        + g2.mul_bigint(base_to_scalar(&c).into_bigint())
        + l.mul_bigint(Scalar::from(3u64).into_bigint());
    let (x, _y) = coords(&acc.into_affine())?;
    Ok(x)
}

/// Challenge bytes: `blake2s(pedersen_hash3(R.x, pk.x, pk.y) ‖ message)`.
fn challenge_bytes(rx: Fr, pk: &PublicKey, message: &[u8]) -> Result<[u8; 32], Error> {
    let (px, py) = coords(pk)?;
    let pde = field_to_be32(&pedersen_hash3(rx, px, py)?);
    let mut hasher = Blake2s256::new();
    hasher.update(pde);
    hasher.update(message);
    Ok(hasher.finalize().into())
}

/// Verify a 64-byte `s ‖ e` signature over an arbitrary-length `message`,
/// exactly as the in-circuit verifier does.
fn verify_bytes(pk: &PublicKey, signature: &[u8; 64], message: &[u8]) -> bool {
    // Reject zero s / e (the circuit's null-signature guard).
    if signature[0..32].iter().all(|&b| b == 0) || signature[32..64].iter().all(|&b| b == 0) {
        return false;
    }
    let s = Scalar::from_be_bytes_mod_order(&signature[0..32]);
    let e = Scalar::from_be_bytes_mod_order(&signature[32..64]);

    // R' = s·G + e·pk.
    let r = (mul_generator(&s) + pk.mul_bigint(e.into_bigint())).into_affine();
    let Ok((rx, _)) = coords(&r) else {
        return false; // r is the identity
    };
    let Ok(challenge) = challenge_bytes(rx, pk, message) else {
        return false;
    };
    challenge == signature[32..64]
}

/// Derive the per-signature nonce `k` deterministically from `(sk, message)`
/// (see the module docs), hedged with `aux` and disambiguated by `counter`.
/// Reduces a 32-byte blake2s digest into the scalar field.
fn derive_nonce(sk: &Scalar, message: &[u8], aux: &[u8; 32], counter: u32) -> Scalar {
    let mut hasher = Blake2s256::new();
    hasher.update(NONCE_DOMAIN);
    hasher.update(field_to_be32(sk));
    hasher.update(aux);
    hasher.update(counter.to_be_bytes());
    hasher.update(message);
    Scalar::from_be_bytes_mod_order(&hasher.finalize())
}

/// Sign an arbitrary-length `message`, producing the 64-byte `s ‖ e` form.
fn sign_bytes<R: Rng>(rng: &mut R, sk: &Scalar, message: &[u8]) -> Result<[u8; 64], Error> {
    let pk = mul_generator(sk).into_affine();
    // Auxiliary entropy hedge — folded into the nonce hash, never relied on.
    let mut aux = [0u8; 32];
    rng.fill_bytes(&mut aux);
    let mut counter = 0u32;
    loop {
        let k = derive_nonce(sk, message, &aux, counter);
        counter = counter.wrapping_add(1);
        if k.is_zero() {
            continue;
        }
        let r = mul_generator(&k).into_affine();
        let Ok((rx, _)) = coords(&r) else {
            continue;
        };

        let e_bytes = challenge_bytes(rx, &pk, message)?;
        let e = Scalar::from_be_bytes_mod_order(&e_bytes);
        if e.is_zero() {
            continue;
        }
        // Verify recomputes R' = s·G + e·pk = (s + e·sk)·G and needs R' = R,
        // so s = k − e·sk.
        let s = k - e * *sk;
        if s.is_zero() {
            continue;
        }
        let mut sig = [0u8; 64];
        sig[0..32].copy_from_slice(&field_to_be32(&s));
        sig[32..64].copy_from_slice(&e_bytes);
        return Ok(sig);
    }
}

/// Sample a keypair.
pub fn keypair<R: Rng>(rng: &mut R) -> (Scalar, PublicKey) {
    let sk = Scalar::rand(rng);
    (sk, mul_generator(&sk).into_affine())
}

/// `pk = [sk]·G`. Infallible today; the `Result` is kept so every call site
/// keeps one shape.
pub fn public_key(sk: &Scalar) -> Result<PublicKey, Error> {
    Ok(mul_generator(sk).into_affine())
}

/// Sign a field payload. The circuit signs the 32-byte big-endian form.
pub fn sign<R: Rng>(rng: &mut R, sk: &Scalar, message: Fr) -> Result<[u8; 64], Error> {
    sign_bytes(rng, sk, &field_to_be32(&message))
}

/// Verify a signature over a field payload.
pub fn verify(pk: &PublicKey, message: Fr, sig: &[u8; 64]) -> bool {
    verify_bytes(pk, sig, &field_to_be32(&message))
}

// ----------------------------------------------------------------------
// NFT key encapsulation.
// ----------------------------------------------------------------------

/// A stored secret scalar that wipes itself on drop and is never *implicitly*
/// copied.
///
/// arkworks field elements are `Copy` and *do* implement [`Zeroize`], but they
/// never zeroize on drop: a `Copy` type cannot have a `Drop` impl, and `Copy`
/// lets the compiler duplicate the value into temporaries a later `.zeroize()`
/// can't reach. Holding a secret in this non-`Copy` newtype from the moment it
/// is produced keeps it to a single, drop-wiped location instead of leaking
/// copies the optimizer makes. Read it only by reference via
/// [`expose`](Self::expose) for the curve arithmetic that needs it; never move
/// or copy the inner value back out.
///
/// Caveat: this cannot un-`Copy` the scalar itself, so transient copies made by
/// the arithmetic that consumes `expose()` (`[sk]·G`, `e·sk`) still live until
/// their stack frames are reused. The guarantee is for the *stored* key, which
/// is the long-lived target.
pub struct SecretScalar(Scalar);

impl SecretScalar {
    /// Wrap a freshly-produced secret scalar.
    pub fn new(secret: Scalar) -> Self {
        Self(secret)
    }

    /// Borrow the inner scalar for curve arithmetic. Do not copy it out.
    pub fn expose(&self) -> &Scalar {
        &self.0
    }
}

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for SecretScalar {}

/// The data that determines `derivedOwner`: the NFT public key (on the
/// embedded curve) and its nonce.
pub struct OwnerSeed {
    /// `nft_pk` on the embedded curve.
    pub pk: PublicKey,
    /// Per-NFT nonce.
    pub nonce: Fr,
}

impl OwnerSeed {
    /// `derivedOwner = poseidon2([pk.x, pk.y, nonce])`, via
    /// [`crate::hash::derive_owner`].
    pub fn derive_owner(&self) -> Result<Fr, Error> {
        crate::hash::derive_owner(&self.pk, self.nonce)
    }
}

/// A retained NFT secret key, held in a wiping [`SecretScalar`].
pub struct NftSecret {
    /// The signing secret. Private + zeroizing: construct via [`NftSecret::new`]
    /// and read it only through [`public_key`](Self::public_key) / signing.
    sk: SecretScalar,
}

impl NftSecret {
    /// Wrap a raw signing secret so it zeroizes on drop.
    pub fn new(sk: Scalar) -> Self {
        Self {
            sk: SecretScalar::new(sk),
        }
    }

    /// `pk = [sk]·G`.
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        public_key(self.sk.expose())
    }
}

/// An NFT signer that keeps its secret key **encapsulated** — the caller
/// gets one of these instead of a raw key. Construct it with
/// [`Signer::local`] (self-issuance) or [`Signer::from_secret`] (bind an
/// existing key).
///
/// Because the signer carries the nonce, a witness builder takes only the
/// signer — there is no separate nonce argument to keep in sync.
///
/// The secret is reachable, explicitly and in two ways: [`Signer::secret`]
/// borrows the [`NftSecret`] and [`Signer::into_secret`] consumes the signer
/// and returns it. Neither yields a raw [`Scalar`] — `NftSecret` keeps its
/// [`SecretScalar`] in a private field and publishes only
/// [`NftSecret::new`] and [`NftSecret::public_key`], so outside this crate the
/// handle can be moved and re-bound with [`Signer::from_secret`] but not read.
/// A caller that takes it is expected to keep it in that wrapper for as long
/// as it lives, and not to reconstruct a bare `Scalar` beside it.
pub struct Signer {
    secret: NftSecret,
    seed: OwnerSeed,
}

impl Signer {
    /// Local self-issuance: generate a fresh NFT key + nonce internally.
    pub fn local(rng: &mut impl Rng) -> Result<Self, Error> {
        let (sk, pk) = keypair(rng);
        let nonce = Fr::rand(rng);
        Ok(Self {
            secret: NftSecret::new(sk),
            seed: OwnerSeed { pk, nonce },
        })
    }

    /// Bind an existing NFT secret to the `nonce` its `derivedOwner`
    /// commits to (recomputes the public key).
    pub fn from_secret(secret: NftSecret, nonce: Fr) -> Result<Self, Error> {
        let pk = secret.public_key()?;
        Ok(Self {
            secret,
            seed: OwnerSeed { pk, nonce },
        })
    }

    /// Borrow the encapsulated NFT secret (e.g. to persist it to a keystore).
    pub fn secret(&self) -> &NftSecret {
        &self.secret
    }

    /// Consume the signer and hand back the NFT secret.
    pub fn into_secret(self) -> NftSecret {
        self.secret
    }

    /// The owner seed (public key + nonce) this signer is bound to.
    pub fn owner_seed(&self) -> &OwnerSeed {
        &self.seed
    }

    /// The NFT public key (its coords are bound via `derivedOwner`).
    pub fn public_key(&self) -> PublicKey {
        self.seed.pk
    }

    /// Sign the ownership `payload`, keeping the secret inside.
    pub fn sign<R: Rng>(&self, rng: &mut R, payload: Fr) -> Result<[u8; 64], Error> {
        sign(rng, self.secret.sk.expose(), payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical Schnorr known-answer vector the Outbe circuits' verifier is
    /// specified against. If our pure-Rust verify reproduces `true` here, the
    /// whole stack (Pedersen generators + blake2s + Grumpkin EC + byte
    /// conventions) is bit-identical to the in-circuit verifier.
    #[test]
    fn canonical_smoke_test_vector() {
        let pk = ark_grumpkin::Affine::new_unchecked(
            grumpkin_fq_from_hex(
                "0x04b260954662e97f00cab9adb773a259097f7a274b83b113532bce27fa3fb96a",
            ),
            grumpkin_fq_from_hex(
                "0x2fd51571db6c08666b0edfbfbc57d432068bccd0110a39b166ab243da0037197",
            ),
        );
        let signature: [u8; 64] = [
            1, 13, 119, 112, 212, 39, 233, 41, 84, 235, 255, 93, 245, 172, 186, 83, 157, 253, 76,
            77, 33, 128, 178, 15, 214, 67, 105, 107, 177, 234, 77, 48, 27, 237, 155, 84, 39, 84,
            247, 27, 22, 8, 176, 230, 24, 115, 145, 220, 254, 122, 135, 179, 171, 4, 214, 202, 64,
            199, 19, 84, 239, 138, 124, 12,
        ];
        let message: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert!(
            verify_bytes(&pk, &signature, &message),
            "canonical KAT must verify"
        );
    }

    /// `pedersen_hash([1, 2, 3])` must match the circuits' value.
    #[test]
    fn pedersen_matches_circuit() {
        let h = pedersen_hash3(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)).unwrap();
        let expected = grumpkin_fq_from_hex(
            "0x0c21b8e26f60b476d9568df4807131ff70d8b7fffb03fa07960aa1cac9be7c46",
        );
        assert_eq!(h, expected);
    }

    /// Our own sign → verify round-trip (same challenge the circuit checks).
    #[test]
    fn sign_verify_round_trip() {
        let mut rng = ark_std::test_rng();
        let (sk, pk) = keypair(&mut rng);
        let message = b"outbe ownership payload bytes----.";
        let sig = sign_bytes(&mut rng, &sk, message).unwrap();
        assert!(verify_bytes(&pk, &sig, message));
        let mut bad = sig;
        bad[40] ^= 1;
        assert!(!verify_bytes(&pk, &bad, message));
    }
}
