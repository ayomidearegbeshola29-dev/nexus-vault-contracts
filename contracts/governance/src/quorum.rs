//! Quorum-decay math for [`Governance`] (issue #392).
//!
//! A proposal's effective quorum starts at the initial `threshold_bps` set at
//! construction and decays **linearly** toward a protocol-safety floor as the
//! voting window elapses, so a proposal that has sat inactive for most of its
//! window needs less "yes" weight to pass. The floor is absolute: decay never
//! lowers the required quorum beneath [`QUORUM_FLOOR_BPS`].

/// Lower bound on the effective quorum, in basis points of total weight.
///
/// The safety minimum: even a fully-window-decayed proposal must still clear
/// this much of the total weight, so a single heavyweight member can never
/// push through a proposal that the rest of the body opposes.
pub const QUORUM_FLOOR_BPS: u32 = 3_500;

/// Effective quorum in basis points for a proposal that has `elapsed` ledgers
/// of its `window`-ledger voting window already behind it.
///
/// The decay is linear: `start_bps` at the first ledger, `QUORUM_FLOOR_BPS`
/// once `elapsed >= window`, and a linear ramp in between. Computed with
/// integer arithmetic only (`u64` intermediate, no fractional loss). The
/// result is clamped to `[QUORUM_FLOOR_BPS, start_bps]`.
pub fn current_quorum_bps(start_bps: u32, elapsed: u32, window: u32) -> u32 {
    if window == 0 {
        return QUORUM_FLOOR_BPS;
    }
    if elapsed >= window {
        return QUORUM_FLOOR_BPS;
    }

    let start = u64::from(start_bps);
    let floor = u64::from(QUORUM_FLOOR_BPS);
    let span = start.saturating_sub(floor);

    let decayed = span * u64::from(elapsed) / u64::from(window);
    let current = start - decayed;

    u32::try_from(current).unwrap_or(QUORUM_FLOOR_BPS)
}
