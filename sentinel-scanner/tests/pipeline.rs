//! End-to-end pipeline test: fake Redis on 127.0.0.1 → scan 127.0.0.1/32
//! limited to that port → assert the scan.json contract fields and the
//! deterministic risk score.

use sentinel_scanner::output::json::{to_json_string, Criticality, Tier, TrustZone};
use sentinel_scanner::{run_scan, ScanConfig};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Deterministic expectation: loopback → mgmt (0.1), default criticality
/// workstation (0.4); Redis -NOAUTH matches CVE-2022-0543 (cvss 10.0,
/// epss 0.44, kev=true — CISA KEV catalog):
///   raw = 10.0*0.25 + 0.44*10*0.35 + 0.1*10*0.25 + 0.4*10*0.15
///       = 2.5 + 1.54 + 0.25 + 0.6 = 4.89
///   KEV override: max(4.89, 9.0) = 9.0  (METHODOLOGY.md R1+R2)
const EXPECTED_RISK_SCORE: f64 = 9.0;
const EXPECTED_CVE: &str = "CVE-2022-0543";

/// Starts a fake Redis server: answers `-NOAUTH` to any inbound bytes.
/// Returns the bound port; the server runs until the task is aborted.
async fn spawn_fake_redis() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind fake redis");
    let port = listener.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _peer)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                // Wait for a probe, then answer like an authenticated Redis.
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await
                {
                    if n > 0 {
                        let _ = sock
                            .write_all(b"-NOAUTH Authentication required.\r\n")
                            .await;
                    }
                }
                // Keep the socket open briefly so the scanner can read.
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
        }
    });
    port
}

fn test_config(port: u16) -> ScanConfig {
    let mut config = ScanConfig::new("127.0.0.1/32", Tier::Daily);
    config.ports = vec![port];
    config.timeout = Duration::from_millis(300);
    config.concurrency = 32;
    config
}

#[tokio::test]
async fn full_pipeline_detects_redis_and_scores_deterministically() {
    let port = spawn_fake_redis().await;
    let report = run_scan(&test_config(port)).await.expect("scan runs");

    // --- Contract top-level fields ---------------------------------------
    assert_eq!(report.target, "127.0.0.1/32");
    assert_eq!(report.tier, Tier::Daily);
    assert!(
        uuid::Uuid::parse_str(&report.scan_id).is_ok(),
        "uuid4 scan_id"
    );
    assert!(
        chrono::DateTime::parse_from_rfc3339(&report.started_at).is_ok(),
        "started_at RFC3339"
    );
    assert!(
        chrono::DateTime::parse_from_rfc3339(&report.finished_at).is_ok(),
        "finished_at RFC3339"
    );

    // --- Host entry --------------------------------------------------------
    assert_eq!(report.hosts.len(), 1, "127.0.0.1 must be live");
    let host = &report.hosts[0];
    assert_eq!(host.ip, "127.0.0.1");
    assert_eq!(host.trust_zone, TrustZone::Mgmt);
    assert_eq!(host.criticality, Criticality::Workstation);
    assert!(host.hostname.is_none());
    assert!(host.mac.is_none());

    // --- Port entry --------------------------------------------------------
    let port_entry = host
        .ports
        .iter()
        .find(|p| p.port == port)
        .expect("scanned port present");
    assert_eq!(port_entry.protocol, "tcp");
    assert_eq!(port_entry.state, "open");
    assert_eq!(port_entry.service.as_deref(), Some("redis"));
    let banner = port_entry.banner.clone().expect("banner captured");
    assert!(banner.contains("NOAUTH"), "banner: {banner}");

    // --- Vulnerability findings -------------------------------------------
    let cves: Vec<&str> = report
        .vulnerabilities
        .iter()
        .map(|v| v.cve_id.as_str())
        .collect();
    assert_eq!(cves, vec![EXPECTED_CVE], "findings: {cves:?}");
    let vuln = &report.vulnerabilities[0];
    assert!((vuln.cvss - 10.0).abs() < f64::EPSILON);
    assert!((vuln.epss - 0.44).abs() < f64::EPSILON);
    assert_eq!(vuln.host, "127.0.0.1");
    assert_eq!(vuln.port, port);
    assert!(!vuln.summary.is_empty());
    // CVE-2022-0543 is on the CISA KEV catalog.
    assert!(vuln.kev, "KEV flag must propagate from cache to report");

    // Banner confidence: -NOAUTH identifies redis without a version → medium.
    assert_eq!(
        port_entry.banner_confidence,
        Some(sentinel_scanner::network::fingerprint::Confidence::Medium),
        "redis banner parse confidence"
    );

    // --- Deterministic risk score ------------------------------------------
    assert_eq!(
        report.risk_score, EXPECTED_RISK_SCORE,
        "deterministic risk score"
    );

    // Re-running the scan yields the identical score and findings.
    let second = run_scan(&test_config(port)).await.expect("second scan");
    assert_eq!(second.risk_score, report.risk_score);
    let second_cves: Vec<&str> = second
        .vulnerabilities
        .iter()
        .map(|v| v.cve_id.as_str())
        .collect();
    assert_eq!(second_cves, cves);

    // --- Serialized JSON keeps the contract shape ---------------------------
    let json = to_json_string(&report).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
    for key in [
        "scan_id",
        "target",
        "tier",
        "started_at",
        "finished_at",
        "hosts",
        "vulnerabilities",
        "risk_score",
    ] {
        assert!(value.get(key).is_some(), "missing top-level key {key}");
    }
    assert_eq!(value["risk_score"], 9.0);
    assert_eq!(value["hosts"][0]["trust_zone"], "mgmt");
    assert_eq!(value["hosts"][0]["ports"][0]["service"], "redis");
    assert_eq!(value["vulnerabilities"][0]["cve_id"], EXPECTED_CVE);
}

#[tokio::test]
async fn scan_of_dead_host_yields_empty_report() {
    // 127.0.0.2 is not expected to run anything in the sandbox.
    let mut config = ScanConfig::new("127.0.0.2/32", Tier::Authority);
    config.ports = vec![1, 2, 3];
    config.timeout = Duration::from_millis(150);
    config.concurrency = 8;
    let report = run_scan(&config).await.expect("scan runs");
    assert!(report.hosts.is_empty());
    assert!(report.vulnerabilities.is_empty());
    assert_eq!(report.risk_score, 0.0);
}

#[tokio::test]
async fn public_scope_is_rejected_without_flag() {
    let mut config = ScanConfig::new("8.8.8.8", Tier::Daily);
    config.timeout = Duration::from_millis(50);
    let err = run_scan(&config).await.expect_err("must reject public ip");
    assert!(matches!(err, sentinel_scanner::ScanError::Scope(_)));
    // ... and accepted with the override flag (scan itself may find nothing).
    config.allow_public = true;
    config.ports = vec![1];
    config.concurrency = 4;
    let report = run_scan(&config).await.expect("allowed with flag");
    assert_eq!(report.target, "8.8.8.8");
}
