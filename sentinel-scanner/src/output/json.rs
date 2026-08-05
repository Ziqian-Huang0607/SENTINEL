//! scan.json serialization per the SPEC interface contract (also the
//! analyzer `ScanInput` schema):
//!
//! ```json
//! {
//!   "scan_id": "uuid4", "target": "192.168.1.0/24",
//!   "tier": "daily|authority|hacker|military",
//!   "started_at": "RFC3339", "finished_at": "RFC3339",
//!   "hosts": [{"ip": "...", "hostname": null, "mac": null, "os_guess": "...",
//!              "trust_zone": "internal", "criticality": "workstation",
//!              "ports": [{"port": 6379, "protocol": "tcp", "state": "open",
//!                         "service": "redis", "version": "6.2.7",
//!                         "banner": "-NOAUTH"}]}],
//!   "vulnerabilities": [{"cve_id": "...", "cvss": 9.8, "epss": 0.85,
//!                        "host": "...", "port": 6379, "summary": "...",
//!                        "kev": false}],
//!   "posture_findings": [{"id": "POSTURE-UNAUTH-WEB", "host": "...",
//!                         "port": 8080, "severity": 6.5, "title": "...",
//!                         "evidence": "GET / -> 200; Server: nginx"}],
//!   "risk_score": 8.97
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;
use thiserror::Error;

/// Errors writing scan output.
#[derive(Debug, Error)]
pub enum OutputError {
    /// Filesystem failure.
    #[error("io error writing {path}: {source}")]
    Io {
        /// Destination path.
        path: String,
        /// Underlying error.
        source: io::Error,
    },
    /// JSON serialization failure.
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// SENTINEL security tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Opportunistic threats; risk threshold < 4.0.
    Daily,
    /// Organized cybercrime; risk threshold < 2.5.
    Authority,
    /// APT / red teams; risk threshold < 1.5.
    Hacker,
    /// Nation-state; risk threshold < 0.5.
    Military,
}

/// Network trust zone of a host (drives EXPOSURE in the risk formula).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustZone {
    /// Publicly reachable.
    Internet,
    /// Demilitarized zone.
    Dmz,
    /// RFC1918 internal network.
    Internal,
    /// Loopback / management network.
    Mgmt,
    /// Physically isolated.
    Airgap,
}

/// Business criticality of a host (drives CRITICALITY in the risk formula).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    /// Domain controller / crown jewels.
    Dc,
    /// Application server.
    App,
    /// End-user workstation (default).
    Workstation,
    /// Embedded / IoT device.
    Iot,
}

/// One open port on a scanned host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortReport {
    /// TCP port number.
    pub port: u16,
    /// Transport protocol (always `tcp` for the connect scanner).
    pub protocol: String,
    /// Port state (`open`).
    pub state: String,
    /// Identified service, if any.
    pub service: Option<String>,
    /// Identified version, if any.
    pub version: Option<String>,
    /// Sanitized banner excerpt, if any.
    pub banner: Option<String>,
    /// Fingerprint parse confidence (`high` = banner + version parsed,
    /// `medium` = service identified without version, `low` = port-hint
    /// fallback). Enables the empirical banner-precision table
    /// (METHODOLOGY.md R4); informational only, never affects scoring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner_confidence: Option<crate::network::fingerprint::Confidence>,
}

/// One live host in the scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostReport {
    /// Host IP address.
    pub ip: String,
    /// Reverse-DNS hostname (null when unknown).
    pub hostname: Option<String>,
    /// Link-layer address (null when unknown; ARP needs privileges).
    pub mac: Option<String>,
    /// OS family guess from port heuristics.
    pub os_guess: Option<String>,
    /// Trust zone driving the EXPOSURE factor.
    pub trust_zone: TrustZone,
    /// Criticality driving the CRITICALITY factor.
    pub criticality: Criticality,
    /// Open ports with fingerprint results.
    pub ports: Vec<PortReport>,
}

/// One matched vulnerability finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnReport {
    /// CVE identifier.
    pub cve_id: String,
    /// CVSS base score.
    pub cvss: f64,
    /// EPSS probability.
    pub epss: f64,
    /// Affected host IP.
    pub host: String,
    /// Affected port.
    pub port: u16,
    /// Short summary from the CVE cache.
    pub summary: String,
    /// CISA KEV catalog membership (from the cve_cache seed). KEV findings
    /// floor the deterministic risk score at 9.0 (scorer.rs, METHODOLOGY.md R2).
    #[serde(default)]
    pub kev: bool,
}

/// Top-level scan.json document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    /// Random UUIDv4 for this scan run.
    pub scan_id: String,
    /// Target expression as supplied by the operator.
    pub target: String,
    /// Security tier.
    pub tier: Tier,
    /// Scan start (RFC3339).
    pub started_at: String,
    /// Scan finish (RFC3339).
    pub finished_at: String,
    /// Live hosts with port/fingerprint detail.
    pub hosts: Vec<HostReport>,
    /// Embedded CVE signature DB provenance (R8 coverage note): lets the
    /// report state exactly what "no CVE matches" was checked against.
    #[serde(default)]
    pub cve_db: CveDbInfo,
    /// Matched vulnerability findings.
    pub vulnerabilities: Vec<VulnReport>,
    /// Exposure findings without a CVE match (unauthenticated interfaces,
    /// legacy cleartext services). Scored through the same deterministic
    /// formula with EPSS = 0. Additive: absent/empty in pre-R8 scan files.
    #[serde(default)]
    pub posture_findings: Vec<PostureReport>,
    /// Deterministic risk score: max per-finding score, rounded to 2dp.
    pub risk_score: f64,
}

/// Provenance of the embedded CVE signature database (R8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveDbInfo {
    /// Seed version string (cve_cache::SEED_VERSION).
    pub version: String,
    /// Number of seeded signatures.
    pub signatures: usize,
}

impl Default for CveDbInfo {
    fn default() -> Self {
        Self {
            version: crate::vuln::cve_cache::SEED_VERSION.to_string(),
            signatures: 0,
        }
    }
}

/// One exposure finding that has no CVE identifier (R8). Unlike a
/// [`VulnReport`] it carries its own pseudo-CVSS severity per class and is
/// always scored with EPSS = 0.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureReport {
    /// Stable finding-class identifier, e.g. `POSTURE-UNAUTH-WEB-GATEWAY`.
    pub id: String,
    /// Affected host IP.
    pub host: String,
    /// Affected port.
    pub port: u16,
    /// Pseudo-CVSS severity for the finding class (posture.rs constants).
    pub severity: f64,
    /// Human-readable finding title.
    pub title: String,
    /// Probe/banner evidence backing the finding.
    pub evidence: String,
}

/// Serializes `report` as pretty JSON to `path`.
pub fn write_scan_json(report: &ScanReport, path: &Path) -> Result<(), OutputError> {
    let text = serde_json::to_string_pretty(report)?;
    std::fs::write(path, format!("{text}\n")).map_err(|source| OutputError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Serializes `report` to a pretty JSON string (used for the analyzer POST).
pub fn to_json_string(report: &ScanReport) -> Result<String, OutputError> {
    Ok(serde_json::to_string_pretty(report)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> ScanReport {
        ScanReport {
            scan_id: "2b7f1516-2818-4b0f-9f10-3b3f1e1a2c3d".to_string(),
            target: "192.168.1.0/24".to_string(),
            tier: Tier::Daily,
            started_at: "2025-01-01T00:00:00+00:00".to_string(),
            finished_at: "2025-01-01T00:00:42+00:00".to_string(),
            hosts: vec![HostReport {
                ip: "192.168.1.45".to_string(),
                hostname: Some("db01".to_string()),
                mac: None,
                os_guess: Some("Linux/Unix (port heuristic)".to_string()),
                trust_zone: TrustZone::Internal,
                criticality: Criticality::Workstation,
                ports: vec![PortReport {
                    port: 6379,
                    protocol: "tcp".to_string(),
                    state: "open".to_string(),
                    service: Some("redis".to_string()),
                    version: None,
                    banner: Some("-NOAUTH".to_string()),
                    banner_confidence: Some(crate::network::fingerprint::Confidence::Medium),
                }],
            }],
            vulnerabilities: vec![VulnReport {
                cve_id: "CVE-2022-0543".to_string(),
                cvss: 10.0,
                epss: 0.44,
                host: "192.168.1.45".to_string(),
                port: 6379,
                summary: "Redis Lua sandbox escape".to_string(),
                kev: true,
            }],
            posture_findings: vec![PostureReport {
                id: "POSTURE-UNAUTH-WEB".to_string(),
                host: "192.168.1.45".to_string(),
                port: 8080,
                severity: 6.5,
                title: "Web interface reachable without authentication".to_string(),
                evidence: "GET / -> 200; Server: nginx".to_string(),
            }],
            cve_db: CveDbInfo {
                version: "2026.08.1".to_string(),
                signatures: 30,
            },
            risk_score: 6.05,
        }
    }

    #[test]
    fn serializes_per_contract_schema() {
        let report = sample_report();
        let text = to_json_string(&report).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid json");

        for key in [
            "scan_id",
            "target",
            "tier",
            "started_at",
            "finished_at",
            "hosts",
            "vulnerabilities",
            "posture_findings",
            "cve_db",
            "risk_score",
        ] {
            assert!(value.get(key).is_some(), "missing key {key}");
        }
        assert_eq!(value["cve_db"]["version"], "2026.08.1");
        assert_eq!(value["cve_db"]["signatures"], 30);
        assert_eq!(value["tier"], "daily");
        let host = &value["hosts"][0];
        assert_eq!(host["trust_zone"], "internal");
        assert_eq!(host["criticality"], "workstation");
        assert!(host.get("mac").is_some());
        let port = &host["ports"][0];
        assert_eq!(port["protocol"], "tcp");
        assert_eq!(port["state"], "open");
        let vuln = &value["vulnerabilities"][0];
        assert_eq!(vuln["cve_id"], "CVE-2022-0543");
        assert_eq!(vuln["port"], 6379);
        assert_eq!(value["risk_score"], 6.05);
    }

    #[test]
    fn roundtrips_through_json() {
        let report = sample_report();
        let text = to_json_string(&report).expect("serialize");
        let back: ScanReport = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(report, back);
    }

    #[test]
    fn pre_r8_scan_json_without_posture_still_parses() {
        // Backward compatibility: scan files written before the R8 posture
        // round have no posture_findings key and must stay valid input.
        let text = to_json_string(&sample_report()).expect("serialize");
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value.as_object_mut().unwrap().remove("posture_findings");
        let back: ScanReport =
            serde_json::from_value(value).expect("deserialize without posture key");
        assert!(back.posture_findings.is_empty());
    }

    #[test]
    fn writes_file_to_disk() {
        let dir = std::env::temp_dir();
        let path = dir.join("sentinel-scanner-json-test.json");
        write_scan_json(&sample_report(), &path).expect("write");
        let text = std::fs::read_to_string(&path).expect("read back");
        std::fs::remove_file(&path).ok();
        assert!(text.contains("\"scan_id\""));
        assert!(text.ends_with('\n'));
    }
}
