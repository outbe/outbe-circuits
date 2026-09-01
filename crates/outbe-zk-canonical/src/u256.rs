//! Host-side encoding for 256-bit circuit amounts.
//!
//! The Emit mint circuit (`outbe.emit.mint@1.5.0`) carries amounts as
//! noir-bignum's `U256`: three little-endian limbs of radix 2^120 (each limb
//! `< 2^120`, top limb `< 2^17`). That shape crosses the ABI as `[u128; 3]`,
//! which is what the generated witness/public-input types expose. Hosts
//! naturally hold amounts as two `u128` halves; these are the exact
//! conversions between the two shapes.

/// Canonical `U256` limbs for the 256-bit amount `hi * 2^128 + lo`.
pub fn to_limbs(hi: u128, lo: u128) -> [u128; 3] {
    const M120: u128 = (1u128 << 120) - 1;
    // `lo >> 120` is 8 bits; `(hi & M112) << 8` fills bits 8..120 without
    // overflowing the limb, so the sum stays below 2^120.
    let mid = (lo >> 120).wrapping_add((hi & ((1u128 << 112) - 1)) << 8);
    [lo & M120, mid & M120, hi >> 112]
}

/// Inverse of [`to_limbs`]: recombines canonical limbs into
/// `(hi, lo)` halves of `hi * 2^128 + lo`.
pub fn from_limbs(limbs: [u128; 3]) -> (u128, u128) {
    let [l0, l1, l2] = limbs;
    let lo = l0 | ((l1 & 0xff) << 120);
    let hi = (l2 << 112) | (l1 >> 8);
    (hi, lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(hi: u128, lo: u128) {
        let (h, l) = from_limbs(to_limbs(hi, lo));
        assert_eq!((h, l), (hi, lo), "roundtrip failed for ({hi}, {lo})");
    }

    #[test]
    fn limb_roundtrip_boundaries() {
        roundtrip(0, 0);
        roundtrip(0, 1);
        roundtrip(0, u128::MAX);
        roundtrip(1, 0);
        roundtrip(u128::MAX, u128::MAX);
        // All-ones amount = 2^256 - 1: canonical limbs are (2^120 - 1,
        // 2^120 - 1, 2^16 - 1).
        let [a, b, c] = to_limbs(u128::MAX, u128::MAX);
        assert_eq!(a, (1u128 << 120) - 1);
        assert_eq!(b, (1u128 << 120) - 1);
        assert_eq!(c, (1u128 << 16) - 1);
    }

    #[test]
    fn limbs_match_radix_decomposition() {
        // 2^200 + 100, built the way the circuit tests build it.
        let limbs = to_limbs(1u128 << 72, 100);
        assert_eq!(limbs, [100, 1u128 << 80, 0]);
    }
}
