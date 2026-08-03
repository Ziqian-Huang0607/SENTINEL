//! Asynchronous TCP-connect port scanner.
//!
//! Unprivileged by design: every probe is a plain TCP connect with an 800ms
//! default timeout. A single global semaphore bounds in-flight connection
//! attempts across *all* host/port pairs (default 200), which keeps a /24
//! (254 hosts) fast without exhausting file descriptors.

use crate::network::packet::ProbeEngine;
use std::net::Ipv4Addr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Errors parsing a `--ports` expression.
#[derive(Debug, Error)]
pub enum PortsError {
    /// A list element was not a port number, range, or known keyword.
    #[error(
        "invalid port spec '{0}': expected 1-65535, a range like 8000-8100, 'top-1000' or 'all'"
    )]
    InvalidSpec(String),
    /// A range whose start is greater than its end.
    #[error("invalid port range '{0}': start must be <= end")]
    BadRange(String),
}

/// Open-port result for a single host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPorts {
    /// Scanned host.
    pub ip: Ipv4Addr,
    /// Open TCP ports, sorted ascending.
    pub open: Vec<u16>,
}

/// Curated high ports (>= 1025) folded into the builtin top-1000 list.
/// Mirrors the high end of nmap's top-1000 service-frequency profile.
const CURATED_HIGH_PORTS: &[u16] = &[
    1026, 1027, 1028, 1029, 1030, 1080, 1099, 1433, 1434, 1521, 1556, 1723, 1900, 2000, 2001, 2049,
    2082, 2083, 2086, 2087, 2095, 2096, 2100, 2222, 2375, 2376, 2483, 2484, 3000, 3128, 3268, 3269,
    3306, 3389, 3690, 4045, 4444, 4445, 4899, 5000, 5001, 5009, 5050, 5051, 5060, 5061, 5222, 5269,
    5432, 5601, 5631, 5632, 5666, 5672, 5900, 5901, 5902, 6000, 6001, 6379, 6464, 6660, 6661, 6662,
    6663, 6664, 6665, 6666, 6667, 6668, 6669, 7000, 7001, 7002, 7100, 7200, 7201, 8000, 8001, 8005,
    8008, 8009, 8010, 8020, 8042, 8069, 8080, 8081, 8082, 8083, 8086, 8087, 8088, 8089, 8090, 8091,
    8098, 8180, 8181, 8222, 8333, 8443, 8500, 8600, 8649, 8888, 9000, 9001, 9002, 9003, 9042, 9090,
    9091, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 10001, 11211, 15672, 27017, 27018,
    27019, 28017, 32768, 49152, 49153, 49154, 50000, 50070, 61613, 61616,
];

/// The builtin "top-1000" port list: the well-known range 1-1024 (which
/// dominates nmap's top-1000 frequency list) union [`CURATED_HIGH_PORTS`],
/// sorted and deduplicated.
pub fn builtin_top_1000() -> Vec<u16> {
    let mut ports: Vec<u16> = (1u16..=1024).collect();
    ports.extend_from_slice(CURATED_HIGH_PORTS);
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Parses a `--ports` expression:
/// - `top-1000` — the builtin list from [`builtin_top_1000`]
/// - `all` — every TCP port, 1-65535
/// - comma-separated ports and inclusive ranges, e.g. `22,80,8000-8100`
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, PortsError> {
    let trimmed = spec.trim();
    match trimmed {
        "top-1000" | "top1000" | "default" => return Ok(builtin_top_1000()),
        "all" => return Ok((1u16..=u16::MAX).collect()),
        _ => {}
    }
    let mut ports: Vec<u16> = Vec::new();
    for part in trimmed.split(',').map(str::trim) {
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .trim()
                .parse()
                .map_err(|_| PortsError::InvalidSpec(part.to_string()))?;
            let end: u16 = end
                .trim()
                .parse()
                .map_err(|_| PortsError::InvalidSpec(part.to_string()))?;
            if start > end {
                return Err(PortsError::BadRange(part.to_string()));
            }
            ports.extend(start..=end);
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| PortsError::InvalidSpec(part.to_string()))?;
            ports.push(port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// TCP-connect scans `ports` on every host in `hosts`.
///
/// Returns one [`HostPorts`] per input host (hosts with no open ports have an
/// empty `open` list), sorted by IP. `concurrency` bounds total in-flight
/// connect attempts across all host/port pairs.
pub async fn scan_hosts(
    hosts: &[Ipv4Addr],
    ports: &[u16],
    engine: ProbeEngine,
    concurrency: usize,
) -> Vec<HostPorts> {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set: JoinSet<(Ipv4Addr, u16, bool)> = JoinSet::new();

    for &host in hosts {
        for &port in ports {
            let permit = Arc::clone(&semaphore);
            set.spawn(async move {
                let _guard = permit.acquire_owned().await.ok();
                let open = engine.tcp_connect(host, port).await;
                (host, port, open)
            });
        }
    }

    let mut results: Vec<HostPorts> = hosts
        .iter()
        .map(|&ip| HostPorts {
            ip,
            open: Vec::new(),
        })
        .collect();
    let index: std::collections::HashMap<Ipv4Addr, usize> =
        hosts.iter().enumerate().map(|(i, &ip)| (ip, i)).collect();

    while let Some(res) = set.join_next().await {
        if let Ok((host, port, true)) = res {
            if let Some(&i) = index.get(&host) {
                if let Some(entry) = results.get_mut(i) {
                    entry.open.push(port);
                }
            }
        }
    }
    for entry in &mut results {
        entry.open.sort_unstable();
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[test]
    fn parses_top_1000_keyword() {
        let ports = parse_ports("top-1000").expect("builtin list");
        assert!(ports.len() >= 1000);
        assert!(ports.contains(&6379));
        assert!(ports.contains(&27017));
        assert!(ports.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn parses_all_keyword() {
        let ports = parse_ports("all").expect("all ports");
        assert_eq!(ports.len(), 65535);
    }

    #[test]
    fn parses_lists_and_ranges() {
        let ports = parse_ports("22, 80, 8000-8002, 22").expect("valid list");
        assert_eq!(ports, vec![22, 80, 8000, 8001, 8002]);
    }

    #[test]
    fn rejects_bad_specs() {
        assert!(parse_ports("http").is_err());
        assert!(parse_ports("9000-8000").is_err());
        assert!(parse_ports("70000").is_err());
    }

    #[tokio::test]
    async fn detects_open_port_on_loopback() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let open_port = listener.local_addr().expect("addr").port();
        let accept =
            tokio::spawn(async move { while let Ok((_sock, _peer)) = listener.accept().await {} });

        // Find a certainly-closed port: bind then release, so it is free.
        let closed_port = {
            let tmp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind");
            let p = tmp.local_addr().expect("addr").port();
            drop(tmp);
            p
        };
        let engine = ProbeEngine::new(Duration::from_millis(300));
        let results = scan_hosts(
            &[Ipv4Addr::LOCALHOST],
            &[open_port, closed_port],
            engine,
            16,
        )
        .await;
        accept.abort();

        assert_eq!(results.len(), 1);
        let host = &results[0];
        assert_eq!(host.ip, Ipv4Addr::LOCALHOST);
        assert!(host.open.contains(&open_port));
        // closed_port may equal open_port-1 which is not listening.
        assert!(!host.open.contains(&closed_port));
    }

    #[tokio::test]
    async fn reports_empty_for_host_with_no_open_ports() {
        let engine = ProbeEngine::new(Duration::from_millis(100));
        let results = scan_hosts(&[Ipv4Addr::new(127, 0, 0, 2)], &[1, 2, 3], engine, 8).await;
        assert_eq!(results.len(), 1);
        assert!(results[0].open.is_empty());
    }
}
