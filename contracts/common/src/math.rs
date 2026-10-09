//! Checked arithmetic helpers for shared financial math (issue #396).
//!
//! Every helper here either returns a mathematically exact result or a
//! [`MathError`] — no saturating fallbacks, no wrapping, no panics. Callers
//! in financial code paths map [`MathError::Overflow`] to
//! [`crate::Error::MathOverflow`] instead of letting a raw `+`/`-`/`*`
//! either trap the contract (debug overflow checks) or silently wrap
//! (release builds, where the same panic path is a correctness hazard for
//! token accounting).
//!
//! # Arithmetic invariants
//!
//! - **Amounts** (`i128`) are token values in stroops; every helper rejects
//!   results that are not exactly representable. Negativity is *not*
//!   rejected here — several flows legitimately carry signed deltas — but
//!   dedicated positivity guards exist where the domain demands them.
//! - **Conversions** between `i128` and `u64` are the truncation danger
//!   zone: [`u64_to_amount`] and [`amount_to_u64`] are total and checked
//!   rather than `as`-casts, which silently truncate.
//! - **Ratios** ([`mul_ratio`], [`apply_fee_bps`]) compute
//!   `value * numerator / denominator` in a single checked pipeline; the
//!   intermediate product is what can overflow even when the final result
//!   fits, so the product itself is checked and [`MathError::Overflow`] is
//!   surfaced before any division happens.
//! - **Denominators** must be non-zero; a zero denominator is a caller bug
//!   and is rejected with [`MathError::DivideByZero`] rather than trapping
//!   on a division by zero.
//!
//! Boundary behaviour at `i128::MAX` and `u64::MAX` is pinned by the unit
//! tests in this module.

use crate::Error;

/// Why a checked arithmetic operation failed.
///
/// Kept separate from [`Error`] so the helpers stay usable in contexts that
/// do not want to depend on the full contract error space; `map_err` into
/// [`Error::MathOverflow`] at the call site.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MathError {
    /// The exact result does not fit in the destination type.
    Overflow,
    /// A denominator (or divisor) was zero.
    DivideByZero,
}

impl From<MathError> for Error {
    fn from(e: MathError) -> Self {
        match e {
            MathError::Overflow | MathError::DivideByZero => Error::MathOverflow,
        }
    }
}

/// Checked `a + b` for token amounts.
pub fn add_amounts(a: i128, b: i128) -> Result<i128, MathError> {
    a.checked_add(b).ok_or(MathError::Overflow)
}

/// Checked `a - b` for token amounts.
pub fn sub_amounts(a: i128, b: i128) -> Result<i128, MathError> {
    a.checked_sub(b).ok_or(MathError::Overflow)
}

/// Checked `a * b` for token amounts.
pub fn mul_amounts(a: i128, b: i128) -> Result<i128, MathError> {
    a.checked_mul(b).ok_or(MathError::Overflow)
}

/// Checked `a / b` for token amounts; rejects a zero divisor instead of
/// trapping.
pub fn div_amounts(a: i128, b: i128) -> Result<i128, MathError> {
    if b == 0 {
        return Err(MathError::DivideByZero);
    }
    // `i128::MIN / -1` is the one division that overflows.
    a.checked_div(b).ok_or(MathError::Overflow)
}

/// Checked cumulative accumulation: `total + delta`, refusing to move a
/// cumulative total past `ceiling` when `ceiling` is provided.
///
/// This is the shape used by every cumulative-refund / cumulative-payout
/// loop: the caller supplies the running total and the per-item delta and
/// gets back either the new total or [`MathError::Overflow`].
pub fn checked_accumulate(
    total: i128,
    delta: i128,
    ceiling: Option<i128>,
) -> Result<i128, MathError> {
    let next = add_amounts(total, delta)?;
    if let Some(cap) = ceiling {
        if next > cap {
            return Err(MathError::Overflow);
        }
    }
    Ok(next)
}

/// Losslessly widen a `u64` counter into an `i128` token amount.
///
/// Every `u64` value is representable as `i128`, so this cannot fail; it
/// exists to give conversions a single audited choke point instead of
/// scattered `as i128` casts.
pub const fn u64_to_amount(v: u64) -> i128 {
    v as i128
}

/// Checked narrowing of an `i128` token amount to a `u64` counter.
///
/// Negative amounts and values above `u64::MAX` are rejected instead of
/// being silently truncated by an `as`-cast.
pub fn amount_to_u64(amount: i128) -> Result<u64, MathError> {
    if amount < 0 {
        return Err(MathError::Overflow);
    }
    u64::try_from(amount).map_err(|_| MathError::Overflow)
}

/// Checked ledger-sequence arithmetic: `base + offset` in `u32` ledger
/// space, saturating the overflow question away by refusing to compute a
/// sequence beyond `u32::MAX`.
pub fn checked_ledger_add(base: u32, offset: u32) -> Result<u32, MathError> {
    base.checked_add(offset).ok_or(MathError::Overflow)
}

/// `value * numerator / denominator`, checked end to end.
///
/// The intermediate product `value * numerator` is computed with
/// [`i128::checked_mul`] *before* the division, so a ratio that would
/// overflow the intermediate width is rejected even when the final result
/// would have fit.
pub fn mul_ratio(value: i128, numerator: i128, denominator: i128) -> Result<i128, MathError> {
    if denominator == 0 {
        return Err(MathError::DivideByZero);
    }
    let product = mul_amounts(value, numerator)?;
    div_amounts(product, denominator)
}

/// Apply a fee expressed in basis points (hundredths of a percent) to
/// `value`, returning the fee portion.
///
/// `fee_bps = 100` is 1%, `fee_bps = 10_000` is 100%. The maximum input
/// accepted is `MAX_FEE_BPS` (100%); anything larger is rejected as an
/// overflow of the bps domain rather than silently paying out more than the
/// value being charged.
pub const MAX_FEE_BPS: u32 = 10_000;

pub fn apply_fee_bps(value: i128, fee_bps: u32) -> Result<i128, MathError> {
    if fee_bps > MAX_FEE_BPS {
        return Err(MathError::Overflow);
    }
    mul_ratio(value, fee_bps as i128, MAX_FEE_BPS as i128)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── add / sub / mul / div ────────────────────────────────────────────

    #[test]
    fn add_sub_roundtrip() {
        assert_eq!(add_amounts(5, 7), Ok(12));
        assert_eq!(sub_amounts(12, 7), Ok(5));
        assert_eq!(sub_amounts(7, 12), Ok(-5));
    }

    #[test]
    fn add_overflow_at_i128_max() {
        assert_eq!(add_amounts(i128::MAX, 1), Err(MathError::Overflow));
        assert_eq!(add_amounts(i128::MAX, i128::MAX), Err(MathError::Overflow));
    }

    #[test]
    fn sub_underflow_at_i128_min() {
        assert_eq!(sub_amounts(i128::MIN, 1), Err(MathError::Overflow));
    }

    #[test]
    fn mul_overflow_rejected() {
        assert_eq!(mul_amounts(i128::MAX, 2), Err(MathError::Overflow));
        assert_eq!(mul_amounts(i128::MAX, -2), Err(MathError::Overflow));
        assert_eq!(mul_amounts(0, i128::MAX), Ok(0));
    }

    #[test]
    fn div_by_zero_rejected_not_trapped() {
        assert_eq!(div_amounts(10, 0), Err(MathError::DivideByZero));
        assert_eq!(div_amounts(0, 0), Err(MathError::DivideByZero));
    }

    #[test]
    fn div_i128_min_by_minus_one_rejected() {
        // The single `checked_div` overflow case.
        assert_eq!(div_amounts(i128::MIN, -1), Err(MathError::Overflow));
        assert_eq!(div_amounts(i128::MIN, 1), Ok(i128::MIN));
    }

    // ── checked_accumulate ───────────────────────────────────────────────

    #[test]
    fn accumulate_respects_ceiling() {
        assert_eq!(checked_accumulate(90, 10, Some(100)), Ok(100));
        assert_eq!(
            checked_accumulate(90, 11, Some(100)),
            Err(MathError::Overflow)
        );
        assert_eq!(
            checked_accumulate(i128::MAX, 1, None),
            Err(MathError::Overflow)
        );
    }

    // ── conversions (truncation hazards) ─────────────────────────────────

    #[test]
    fn u64_max_roundtrips_through_i128() {
        assert_eq!(u64_to_amount(u64::MAX), u64::MAX as i128);
        assert_eq!(amount_to_u64(u64::MAX as i128), Ok(u64::MAX));
    }

    #[test]
    fn amount_to_u64_rejects_negative_and_too_large() {
        assert_eq!(amount_to_u64(-1), Err(MathError::Overflow));
        assert_eq!(
            amount_to_u64(u64::MAX as i128 + 1),
            Err(MathError::Overflow)
        );
        assert_eq!(amount_to_u64(i128::MAX), Err(MathError::Overflow));
    }

    // ── ledger arithmetic ────────────────────────────────────────────────

    #[test]
    fn ledger_add_bounds() {
        assert_eq!(checked_ledger_add(100, 200), Ok(300));
        assert_eq!(checked_ledger_add(u32::MAX, 1), Err(MathError::Overflow));
        assert_eq!(checked_ledger_add(u32::MAX, 0), Ok(u32::MAX));
    }

    // ── ratios and fees ──────────────────────────────────────────────────

    #[test]
    fn ratio_exact_and_rounded_down() {
        assert_eq!(mul_ratio(1000, 50, 100), Ok(500));
        // Integer division rounds toward zero, as everywhere else in the
        // codebase's fee math.
        assert_eq!(mul_ratio(999, 50, 100), Ok(499));
    }

    #[test]
    fn ratio_zero_denominator_rejected() {
        assert_eq!(mul_ratio(1000, 50, 0), Err(MathError::DivideByZero));
    }

    #[test]
    fn ratio_intermediate_overflow_rejected_even_when_result_fits() {
        // The result 1 fits trivially, but the intermediate product would
        // overflow — the pipeline must reject it rather than wrap.
        assert_eq!(
            mul_ratio(i128::MAX, i128::MAX, i128::MAX),
            Err(MathError::Overflow)
        );
    }

    #[test]
    fn fee_bps_boundaries() {
        assert_eq!(apply_fee_bps(10_000, 0), Ok(0));
        assert_eq!(apply_fee_bps(10_000, 100), Ok(100)); // 1%
        assert_eq!(apply_fee_bps(10_000, 10_000), Ok(10_000)); // 100%
        assert_eq!(apply_fee_bps(10_000, 10_001), Err(MathError::Overflow));
        // `i128::MAX` value with a 1% fee overflows the intermediate product.
        assert_eq!(apply_fee_bps(i128::MAX, 100), Err(MathError::Overflow));
    }

    // ── error mapping ────────────────────────────────────────────────────

    #[test]
    fn math_error_maps_to_contract_error() {
        let e: Error = MathError::Overflow.into();
        assert_eq!(e, Error::MathOverflow);
        let e: Error = MathError::DivideByZero.into();
        assert_eq!(e, Error::MathOverflow);
    }
}
