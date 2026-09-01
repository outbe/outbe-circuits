//! Host-side encoding for 256-bit circuit amounts.
//!
//! The Emit mint circuit (`outbe.emit.mint@1.5.0`) carries amounts as
//! noir-bignum's `U256`: three little-endian limbs of radix 2^120 (the first
//! two limbs are `< 2^120`, the top limb is `< 2^16`). That shape crosses the
//! ABI as `[u128; 3]`; this module converts directly to and from Alloy's
//! `U256`.

use alloy_primitives::U256;

/// Canonical noir-bignum limbs for an Alloy `U256`.
pub fn to_limbs(value: U256) -> [u128; 3] {
    const M120: u128 = (1u128 << 120) - 1;
    let words = value.as_limbs();
    let lo = u128::from(words[0]) | (u128::from(words[1]) << 64);
    let hi = u128::from(words[2]) | (u128::from(words[3]) << 64);
    let mid = (lo >> 120) | ((hi & ((1u128 << 112) - 1)) << 8);
    [lo & M120, mid, hi >> 112]
}

/// Recombine canonical noir-bignum limbs into an Alloy `U256`.
///
/// Returns `None` rather than aliasing a non-canonical ABI representation.
pub fn from_limbs(limbs: [u128; 3]) -> Option<U256> {
    let [l0, l1, l2] = limbs;
    if l0 >= 1u128 << 120 || l1 >= 1u128 << 120 || l2 >= 1u128 << 16 {
        return None;
    }
    let lo = l0 | ((l1 & 0xff) << 120);
    let hi = (l2 << 112) | (l1 >> 8);
    Some(U256::from_limbs([
        lo as u64,
        (lo >> 64) as u64,
        hi as u64,
        (hi >> 64) as u64,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: U256) {
        assert_eq!(from_limbs(to_limbs(value)), Some(value));
    }

    #[test]
    fn limb_roundtrip_boundaries() {
        roundtrip(U256::ZERO);
        roundtrip(U256::from(1));
        roundtrip(U256::from(u128::MAX));
        roundtrip(U256::from(1) << 128);
        roundtrip(U256::MAX);

        assert_eq!(
            to_limbs(U256::MAX),
            [(1u128 << 120) - 1, (1u128 << 120) - 1, (1u128 << 16) - 1,]
        );
    }

    #[test]
    fn limbs_match_radix_decomposition() {
        let value = (U256::from(1) << 200) + U256::from(100);
        assert_eq!(to_limbs(value), [100, 1u128 << 80, 0]);
    }

    #[test]
    fn non_canonical_limbs_are_rejected() {
        assert_eq!(from_limbs([1u128 << 120, 0, 0]), None);
        assert_eq!(from_limbs([0, 1u128 << 120, 0]), None);
        assert_eq!(from_limbs([0, 0, 1u128 << 16]), None);
    }
}
