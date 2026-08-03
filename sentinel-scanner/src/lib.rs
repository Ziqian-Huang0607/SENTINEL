//! sentinel-scanner: SENTINEL core scanner engine.
//!
//! Pipeline: scope parsing → host discovery → TCP-connect port scan →
//! service fingerprinting → CVE matching → deterministic risk scoring →
//! scan.json per the SPEC contract. Fully unprivileged (TCP connect based);
//! an optional privileged raw-socket ICMP path lives behind the
//! `privileged` cargo feature.

pub mod config;
pub mod network;
pub mod output;
pub mod vuln;

pub use output::json::{
    Criticality, HostReport, PortReport, ScanReport, Tier, TrustZone, VulnReport,
};

use crate::config::scope::{Scope, ScopeError};
use crate::network::discovery::discover_hosts;
use crate::network::fingerprint::{fingerprint_port, guess_os, Fingerprint};
use crate::network::packet::ProbeEngine;
use crate::network::portscan::scan_hosts;
use crate::vuln::cve_cache::{CveCache, CveCacheError};
use crate::vuln::matcher::match_cves;
use crate::vuln::scorer::scan_risk_score;
use chrono::Utc;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use uuid::Uuid;

/// Default per-connection timeout (SPEC: 800ms).
pub const DEFAULT_TIMEOUT_MS: u64 = 800;
/// Default scan concurrency (SPEC: 200).
pub const DEFAULT_CONCURRENCY: usize = 200;
/// Scopes with at most this many hosts skip the discovery pre-filter
/// entirely (discovery is a large-scope optimization; for a handful of
/// targets we port-scan every one of them, like nmap's `-Pn`).
pub const SMALL_SCOPE_DISCOVERY_SKIP: usize = 8;

/// Everything needed to run one scan.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Target expression: CIDR, single IP, or comma-separated list.
    pub target: String,
    /// Security tier for this scan.
    pub tier: Tier,
    /// Allow scanning public (non-RFC1918/loopback) address space.
    pub allow_public: bool,
    /// Maximum in-flight connection attempts.
    pub concurrency: usize,
    /// Ports to scan per host.
    pub ports: Vec<u16>,
    /// Per-connection timeout.
    pub timeout: Duration,
    /// Optional trust-zone override applied to every host.
    pub trust_zone: Option<TrustZone>,
    /// Optional criticality override applied to every host.
    pub criticality: Option<Criticality>,
    /// Skip host discovery and port-scan every host in scope (`-Pn`).
    /// Automatically true for scopes of <= [`SMALL_SCOPE_DISCOVERY_SKIP`].
    pub skip_discovery: bool,
}

impl ScanConfig {
    /// Builds a config with SPEC defaults; the caller adjusts fields as needed.
    pub fn new(target: impl Into<String>, tier: Tier) -> Self {
        Self {
            target: target.into(),
            tier,
            allow_public: false,
            concurrency: DEFAULT_CONCURRENCY,
            ports: network::portscan::builtin_top_1000(),
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            trust_zone: None,
            criticality: None,
            skip_discovery: false,
        }
    }
}

/// Errors a scan run can produce.
#[derive(Debug, Error)]
pub enum ScanError {
    /// Target scope invalid or out of policy.
    #[error(transparent)]
    Scope(#[from] ScopeError),
    /// CVE cache failure.
    #[error(transparent)]
    Cache(#[from] CveCacheError),
}

/// Default trust-zone assignment: loopback → mgmt, private/local → internal,
/// anything else (reachable only with `--allow-public`) → internet.
pub fn default_trust_zone(ip: &Ipv4Addr) -> TrustZone {
    if ip.is_loopback() {
        TrustZone::Mgmt
    } else if config::scope::is_private_or_local(ip) {
        TrustZone::Internal
    } else {
        TrustZone::Internet
    }
}

/// Runs the full scan pipeline and returns the contract scan report.
pub async fn run_scan(config: &ScanConfig) -> Result<ScanReport, ScanError> {
    let started_at = Utc::now();
    let scope = Scope::parse(&config.target, config.allow_public)?;
    let engine = ProbeEngine::new(config.timeout);

    // Stage 1+2: discovery (skipped for small scopes / on request), then
    // connect-scan of the candidate hosts. Only hosts with at least one open
    // port are reported.
    let skip_discovery = config.skip_discovery || scope.hosts.len() <= SMALL_SCOPE_DISCOVERY_SKIP;
    let candidates = if skip_discovery {
        scope.hosts.clone()
    } else {
        discover_hosts(&scope.hosts, engine, config.concurrency).await
    };
    let scanned = scan_hosts(&candidates, &config.ports, engine, config.concurrency).await;
    let scanned: Vec<_> = scanned.into_iter().filter(|h| !h.open.is_empty()).collect();

    // Stage 3: fingerprint every open port (concurrency-bounded).
    let fingerprints = fingerprint_all(&scanned, engine, config.concurrency).await;

    // Stage 4+5: match CVEs and score deterministically.
    let cache = CveCache::in_memory()?;
    let criticality = config.criticality.unwrap_or(Criticality::Workstation);

    let mut hosts: Vec<HostReport> = Vec::new();
    let mut vulnerabilities: Vec<VulnReport> = Vec::new();
    let mut score_args: Vec<(f64, f64, bool, TrustZone, Criticality)> = Vec::new();

    for host in &scanned {
        let zone = config
            .trust_zone
            .unwrap_or_else(|| default_trust_zone(&host.ip));

        let mut ports: Vec<PortReport> = Vec::new();
        for &port in &host.open {
            let fp = fingerprints
                .get(&(host.ip, port))
                .cloned()
                .unwrap_or_default();
            if let Some(service) = fp.service.as_deref() {
                let version = fp.version.as_deref();
                for entry in match_cves(&cache, service, version)? {
                    vulnerabilities.push(VulnReport {
                        cve_id: entry.cve_id.clone(),
                        cvss: entry.cvss,
                        epss: entry.epss,
                        host: host.ip.to_string(),
                        port,
                        summary: entry.summary.clone(),
                        kev: entry.kev,
                    });
                    score_args.push((entry.cvss, entry.epss, entry.kev, zone, criticality));
                }
            }
            ports.push(PortReport {
                port,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                banner_confidence: fp.service.as_ref().map(|_| fp.confidence),
                service: fp.service,
                version: fp.version,
                banner: fp.banner,
            });
        }

        hosts.push(HostReport {
            ip: host.ip.to_string(),
            hostname: None,
            mac: None,
            os_guess: guess_os(&host.open),
            trust_zone: zone,
            criticality,
            ports,
        });
    }

    let finished_at = Utc::now();
    let risk_score = scan_risk_score(
        score_args
            .iter()
            .map(|(cvss, epss, kev, zone, crit)| (*cvss, *epss, *kev, zone, crit)),
    );

    Ok(ScanReport {
        scan_id: Uuid::new_v4().to_string(),
        target: config.target.clone(),
        tier: config.tier,
        started_at: started_at.to_rfc3339(),
        finished_at: finished_at.to_rfc3339(),
        hosts,
        vulnerabilities,
        risk_score,
    })
}

/// Fingerprints every open port of every scanned host, returning a
/// `(ip, port) -> Fingerprint` map.
async fn fingerprint_all(
    scanned: &[network::portscan::HostPorts],
    engine: ProbeEngine,
    concurrency: usize,
) -> HashMap<(Ipv4Addr, u16), Fingerprint> {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set: JoinSet<((Ipv4Addr, u16), Fingerprint)> = JoinSet::new();

    for host in scanned {
        for &port in &host.open {
            let permit = Arc::clone(&semaphore);
            let ip = host.ip;
            set.spawn(async move {
                let _guard = permit.acquire_owned().await.ok();
                let fp = fingerprint_port(ip, port, engine).await;
                ((ip, port), fp)
            });
        }
    }

    let mut out = HashMap::new();
    while let Some(res) = set.join_next().await {
        if let Ok((key, fp)) = res {
            out.insert(key, fp);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_zone_defaults() {
        assert_eq!(
            default_trust_zone(&Ipv4Addr::new(127, 0, 0, 1)),
            TrustZone::Mgmt
        );
        assert_eq!(
            default_trust_zone(&Ipv4Addr::new(192, 168, 1, 5)),
            TrustZone::Internal
        );
        assert_eq!(
            default_trust_zone(&Ipv4Addr::new(10, 0, 0, 9)),
            TrustZone::Internal
        );
        assert_eq!(
            default_trust_zone(&Ipv4Addr::new(8, 8, 8, 8)),
            TrustZone::Internet
        );
    }

    #[test]
    fn config_defaults_match_spec() {
        let cfg = ScanConfig::new("127.0.0.1/32", Tier::Daily);
        assert_eq!(cfg.concurrency, 200);
        assert_eq!(cfg.timeout, Duration::from_millis(800));
        assert!(cfg.ports.len() >= 1000);
        assert!(!cfg.allow_public);
    }
}
