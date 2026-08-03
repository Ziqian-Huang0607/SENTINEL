//! Deterministic risk scoring (SPEC — must match exactly):
//!
//! ```text
//! RISK_SCORE = (CVSS * 0.25) + (EPSS * 10 * 0.35)
//!            + (EXPOSURE * 10 * 0.25) + (CRITICALITY * 10 * 0.15)
//! ```
//! EXPOSURE:     internet 1.0, dmz 0.7, internal 0.4, mgmt 0.1, airgap 0.0
//! CRITICALITY:  dc 1.0, app 0.7, workstation 0.4, iot 0.1
//!
//! KEV override: findings on the CISA Known Exploited Vulnerabilities
//! catalog floor at KEV_RISK_FLOOR (9.0) — `max(raw, 9.0)` per finding
//! before the scan-level max.
//!
//! The scan-level risk score is the maximum per-finding score, rounded to
//! two decimals; a scan with no findings scores 0.0.
//!
//! Evidence: METHODOLOGY.md Ch.8 R1 (EPSS-dominant weighting, EPSS v3/v4,
//! DTRAP 2021) and R2 (KEV escalation; EPSS pre-flags <20% of KEV-bound
//! CVEs; BOD 26-04 tiered SLA triggers).

use crate::output::json::{Criticality, TrustZone};

/// Weight applied to the CVSS term.
pub const W_CVSS: f64 = 0.25;
/// Weight applied to the EPSS term (EPSS scaled by 10).
pub const W_EPSS: f64 = 0.35;
/// Weight applied to the exposure term (exposure scaled by 10).
pub const W_EXPOSURE: f64 = 0.25;
/// Weight applied to the criticality term (criticality scaled by 10).
pub const W_CRITICALITY: f64 = 0.15;
/// Floor applied to KEV-catalog findings (critical band).
pub const KEV_RISK_FLOOR: f64 = 9.0;

/// EXPOSURE mapping table (SPEC).
pub fn exposure_weight(zone: TrustZone) -> f64 {
    match zone {
        TrustZone::Internet => 1.0,
        TrustZone::Dmz => 0.7,
        TrustZone::Internal => 0.4,
        TrustZone::Mgmt => 0.1,
        TrustZone::Airgap => 0.0,
    }
}

/// CRITICALITY mapping table (SPEC).
pub fn criticality_weight(criticality: Criticality) -> f64 {
    match criticality {
        Criticality::Dc => 1.0,
        Criticality::App => 0.7,
        Criticality::Workstation => 0.4,
        Criticality::Iot => 0.1,
    }
}

/// The exact deterministic per-finding formula (unrounded).
pub fn score_finding(cvss: f64, epss: f64, zone: TrustZone, criticality: Criticality) -> f64 {
    cvss * W_CVSS
        + epss * 10.0 * W_EPSS
        + exposure_weight(zone) * 10.0 * W_EXPOSURE
        + criticality_weight(criticality) * 10.0 * W_CRITICALITY
}

/// Per-finding formula with the KEV override: KEV-catalog findings floor
/// at KEV_RISK_FLOOR regardless of the raw score.
pub fn score_finding_kev(
    cvss: f64,
    epss: f64,
    zone: TrustZone,
    criticality: Criticality,
    kev: bool,
) -> f64 {
    let raw = score_finding(cvss, epss, zone, criticality);
    if kev { raw.max(KEV_RISK_FLOOR) } else { raw }
}

/// Rounds to two decimal places (half away from zero).
///
/// Adds a 1e-9 nudge (in centi units) before rounding to counteract binary
/// floating-point representation error: the exact SPEC arithmetic for e.g.
/// 9.8/0.85/internal/workstation yields 6.864999999999999 in f64, which must
/// still round to the decimal-expected 6.87. The nudge is far below any real
/// score difference, so behavior stays deterministic and faithful.
pub fn round2(value: f64) -> f64 {
    (value * 100.0 + 1e-9).round() / 100.0
}

/// Scan-level risk score: maximum per-finding score, rounded to 2dp.
/// Returns 0.0 when there are no findings.
///
/// Each item is `(cvss, epss, kev, zone, criticality)`; `kev` applies the
/// KEV_RISK_FLOOR override for that finding.
pub fn scan_risk_score<'a, I>(findings: I) -> f64
where
    I: IntoIterator<Item = (f64, f64, bool, &'a TrustZone, &'a Criticality)>,
{
    let max = findings
        .into_iter()
        .map(|(cvss, epss, kev, zone, crit)| score_finding_kev(cvss, epss, *zone, *crit, kev))
        .fold(0.0_f64, f64::max);
    round2(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-computed: 9.8*0.25 + 0.85*10*0.35 + 0.4*10*0.25 + 0.4*10*0.15
    /// = 2.45 + 2.975 + 1.0 + 0.6 = 7.025 -> 7.03 rounded.
    #[test]
    fn spec_example_hand_computed() {
        let raw = score_finding(9.8, 0.85, TrustZone::Internal, Criticality::Workstation);
        assert!((raw - 7.025).abs() < 1e-9);
        assert_eq!(round2(raw), 7.03);
    }

    /// KEV override: a low raw score floors at 9.0 when kev=true; identical
    /// inputs with kev=false stay raw.
    #[test]
    fn kev_finding_floors_at_9() {
        let raw = score_finding(4.0, 0.1, TrustZone::Internal, Criticality::Workstation);
        assert!((raw - 2.95).abs() < 1e-9);
        let floored = score_finding_kev(4.0, 0.1, TrustZone::Internal, Criticality::Workstation, true);
        assert_eq!(floored, KEV_RISK_FLOOR);
        let unfloored =
            score_finding_kev(4.0, 0.1, TrustZone::Internal, Criticality::Workstation, false);
        assert_eq!(unfloored, raw);
        // A KEV finding already above the floor keeps its raw score.
        let high = score_finding_kev(9.8, 0.85, TrustZone::Internet, Criticality::Dc, true);
        assert!((high - 9.425).abs() < 1e-9);
    }

    #[test]
    fn exposure_table_matches_spec() {
        assert_eq!(exposure_weight(TrustZone::Internet), 1.0);
        assert_eq!(exposure_weight(TrustZone::Dmz), 0.7);
        assert_eq!(exposure_weight(TrustZone::Internal), 0.4);
        assert_eq!(exposure_weight(TrustZone::Mgmt), 0.1);
        assert_eq!(exposure_weight(TrustZone::Airgap), 0.0);
    }

    #[test]
    fn criticality_table_matches_spec() {
        assert_eq!(criticality_weight(Criticality::Dc), 1.0);
        assert_eq!(criticality_weight(Criticality::App), 0.7);
        assert_eq!(criticality_weight(Criticality::Workstation), 0.4);
        assert_eq!(criticality_weight(Criticality::Iot), 0.1);
    }

    /// Property: every term is non-negative and bounded, so any finding with
    /// cvss<=10, epss<=1 must score in [0, 10].
    #[test]
    fn scores_stay_within_0_to_10() {
        let zones = [
            TrustZone::Internet,
            TrustZone::Dmz,
            TrustZone::Internal,
            TrustZone::Mgmt,
            TrustZone::Airgap,
        ];
        let crits = [
            Criticality::Dc,
            Criticality::App,
            Criticality::Workstation,
            Criticality::Iot,
        ];
        for zone in zones {
            for crit in crits {
                for cvss in [0.0, 3.1, 7.5, 10.0] {
                    for epss in [0.0, 0.5, 1.0] {
                        let s = score_finding(cvss, epss, zone, crit);
                        assert!((0.0..=10.0).contains(&s), "score {s} out of range");
                    }
                }
            }
        }
    }

    /// Property: raising any single input factor never lowers the score.
    #[test]
    fn score_is_monotonic_in_each_factor() {
        let base = score_finding(5.0, 0.2, TrustZone::Internal, Criticality::Workstation);
        assert!(score_finding(6.0, 0.2, TrustZone::Internal, Criticality::Workstation) >= base);
        assert!(score_finding(5.0, 0.4, TrustZone::Internal, Criticality::Workstation) >= base);
        assert!(score_finding(5.0, 0.2, TrustZone::Dmz, Criticality::Workstation) >= base);
        assert!(score_finding(5.0, 0.2, TrustZone::Internal, Criticality::App) >= base);
    }

    #[test]
    fn worst_case_is_internet_dc() {
        // 10*0.25 + 1*10*0.35 + 1*10*0.25 + 1*10*0.15 = 2.5+3.5+2.5+1.5 = 10
        let s = score_finding(10.0, 1.0, TrustZone::Internet, Criticality::Dc);
        assert_eq!(round2(s), 10.0);
        // Best case: minimum criticality weight is iot 0.1, so the floor for
        // any finding is 0.1*10*0.15 = 0.15.
        let s = score_finding(0.0, 0.0, TrustZone::Airgap, Criticality::Iot);
        assert_eq!(round2(s), 0.15);
    }

    #[test]
    fn scan_score_is_max_rounded_and_zero_when_empty() {
        let empty: Vec<(f64, f64, bool, &TrustZone, &Criticality)> = Vec::new();
        assert_eq!(scan_risk_score(empty), 0.0);

        let findings = [
            (4.0, 0.1, false, &TrustZone::Internal, &Criticality::Workstation),
            (9.8, 0.85, false, &TrustZone::Internal, &Criticality::Workstation),
            (7.0, 0.5, false, &TrustZone::Mgmt, &Criticality::Iot),
        ];
        // Max is the 9.8/0.85 finding: 7.025 -> 7.03.
        assert_eq!(scan_risk_score(findings), 7.03);

        // A KEV finding escalates the scan score to the 9.0 floor.
        let kev_findings = [
            (4.0, 0.1, true, &TrustZone::Internal, &Criticality::Workstation),
            (9.8, 0.85, false, &TrustZone::Internal, &Criticality::Workstation),
        ];
        assert_eq!(scan_risk_score(kev_findings), 9.0);
    }

    #[test]
    fn round2_behaves_at_half_boundaries() {
        assert_eq!(round2(6.865), 6.87);
        assert_eq!(round2(5.15), 5.15);
        assert_eq!(round2(0.004), 0.0);
        assert_eq!(round2(0.005), 0.01);
    }
}
