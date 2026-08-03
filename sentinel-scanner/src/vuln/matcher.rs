//! Fingerprint → CVE candidate matching.
//!
//! Matching is deterministic:
//! - candidates come from [`CveCache::find_by_service`] (exact canonical
//!   service name, seed order);
//! - entries **without** a version range always match;
//! - entries **with** a version range match when the fingerprint version is
//!   known and falls inside `[version_start, version_end)`;
//! - entries with a version range are *not* matched when the fingerprint has
//!   no version (we cannot establish exposure, so we avoid noise).

use crate::vuln::cve_cache::{CveCache, CveCacheError, CveEntry};
use std::cmp::Ordering;

/// Compares two normalized dotted version strings numerically,
/// e.g. `9.6.1` vs `9.8` (missing components count as zero, so
/// `9.6` == `9.6.0`). Non-numeric input is treated component-wise as 0.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let pa = parse_version(a);
    let pb = parse_version(b);
    let len = pa.len().max(pb.len());
    for i in 0..len {
        let x = pa.get(i).copied().unwrap_or(0);
        let y = pb.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// Splits a dotted version string into numeric components.
fn parse_version(v: &str) -> Vec<u64> {
    v.split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0))
        .collect()
}

/// True when `version` lies in `[start, end)` (either bound may be open).
pub fn version_in_range(version: &str, start: Option<&str>, end: Option<&str>) -> bool {
    if let Some(s) = start {
        if compare_versions(version, s) == Ordering::Less {
            return false;
        }
    }
    if let Some(e) = end {
        if compare_versions(version, e) != Ordering::Less {
            return false;
        }
    }
    true
}

/// True when `entry` applies to a service with `version` (None = unknown).
pub fn entry_matches(entry: &CveEntry, version: Option<&str>) -> bool {
    if !entry.has_version_range() {
        return true;
    }
    match version {
        Some(v) => version_in_range(
            v,
            entry.version_start.as_deref(),
            entry.version_end.as_deref(),
        ),
        None => false,
    }
}

/// Maps a fingerprint to matching CVE candidates from the cache.
pub fn match_cves(
    cache: &CveCache,
    service: &str,
    version: Option<&str>,
) -> Result<Vec<CveEntry>, CveCacheError> {
    let candidates = cache.find_by_service(service)?;
    Ok(candidates
        .into_iter()
        .filter(|entry| entry_matches(entry, version))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_dotted_versions_numerically() {
        assert_eq!(compare_versions("9.6.1", "9.8"), Ordering::Less);
        assert_eq!(compare_versions("9.8", "9.6.1"), Ordering::Greater);
        assert_eq!(compare_versions("9.6", "9.6.0"), Ordering::Equal);
        assert_eq!(compare_versions("2.4.49", "2.4.49"), Ordering::Equal);
        assert_eq!(compare_versions("10.0.0", "9.9.9"), Ordering::Greater);
    }

    #[test]
    fn range_check_is_start_inclusive_end_exclusive() {
        assert!(version_in_range("2.4.49", Some("2.4.49"), Some("2.4.50")));
        assert!(!version_in_range("2.4.50", Some("2.4.49"), Some("2.4.50")));
        assert!(version_in_range("8.5", Some("8.5"), Some("9.8")));
        assert!(!version_in_range("9.8", Some("8.5"), Some("9.8")));
        assert!(version_in_range("1.0", None, Some("2.0")));
        assert!(!version_in_range("2.0", None, Some("2.0")));
        assert!(version_in_range("99.0", Some("1.0"), None));
    }

    #[test]
    fn ranged_entry_needs_known_version() {
        let cache = CveCache::in_memory().expect("cache");
        // Apache 2.4.49 -> CVE-2021-41773 only.
        let hits = match_cves(&cache, "apache", Some("2.4.49")).expect("match");
        let ids: Vec<&str> = hits.iter().map(|e| e.cve_id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-2021-41773"]);

        // Unknown version: ranged entries are skipped, and apache has no
        // range-less entries, so nothing matches.
        let hits = match_cves(&cache, "apache", None).expect("match");
        assert!(hits.is_empty());
    }

    #[test]
    fn rangeless_entry_matches_without_version() {
        let cache = CveCache::in_memory().expect("cache");
        let hits = match_cves(&cache, "redis", None).expect("match");
        let ids: Vec<&str> = hits.iter().map(|e| e.cve_id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-2022-0543"]);
    }

    #[test]
    fn version_narrows_ranged_matches() {
        let cache = CveCache::in_memory().expect("cache");
        // OpenSSH 9.6 is inside CVE-2024-6387's [8.5, 9.8) range only.
        let hits = match_cves(&cache, "openssh", Some("9.6.1")).expect("match");
        let ids: Vec<&str> = hits.iter().map(|e| e.cve_id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-2024-6387"]);

        // OpenSSH 7.4 matches CVE-2023-38408, CVE-2021-28041, CVE-2018-15473.
        let hits = match_cves(&cache, "openssh", Some("7.4")).expect("match");
        let ids: Vec<&str> = hits.iter().map(|e| e.cve_id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["CVE-2023-38408", "CVE-2021-28041", "CVE-2018-15473"]
        );
    }

    #[test]
    fn smb_exposure_entries_match_versionless() {
        let cache = CveCache::in_memory().expect("cache");
        let hits = match_cves(&cache, "smb", None).expect("match");
        let ids: Vec<&str> = hits.iter().map(|e| e.cve_id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-2017-0144", "CVE-2020-0796"]);
    }
}
