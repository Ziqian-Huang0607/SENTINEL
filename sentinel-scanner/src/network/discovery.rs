//! Host discovery.
//!
//! Prefers ICMP echo when the privileged raw-socket path is compiled in and
//! usable; otherwise (the default, unprivileged case) probes a small set of
//! commonly-open TCP ports with plain connects. A host is considered live
//! when any probe succeeds. Concurrency is bounded with a semaphore.

use crate::network::packet::ProbeEngine;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// TCP ports used for unprivileged host discovery, most-common first.
/// (SPEC: 80, 443, 22, 445, 3389, 8080.)
pub const DISCOVERY_PORTS: [u16; 6] = [80, 443, 22, 445, 3389, 8080];

/// Discovers live hosts among `hosts` using [`DISCOVERY_PORTS`].
///
/// Returns the sorted list of hosts that answered at least one probe.
/// `concurrency` bounds the number of in-flight probe tasks.
pub async fn discover_hosts(
    hosts: &[Ipv4Addr],
    engine: ProbeEngine,
    concurrency: usize,
) -> Vec<Ipv4Addr> {
    discover_hosts_with_ports(hosts, engine, concurrency, &DISCOVERY_PORTS).await
}

/// Discovery with an explicit probe-port list (used by tests and by the
/// default wrapper above).
pub async fn discover_hosts_with_ports(
    hosts: &[Ipv4Addr],
    engine: ProbeEngine,
    concurrency: usize,
    ports: &[u16],
) -> Vec<Ipv4Addr> {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let use_icmp = engine.icmp_available();
    let ports: Arc<[u16]> = Arc::from(ports);
    let mut set: JoinSet<(Ipv4Addr, bool)> = JoinSet::new();

    for &host in hosts {
        let permit = Arc::clone(&semaphore);
        let probe_ports = Arc::clone(&ports);
        set.spawn(async move {
            let _guard = permit.acquire_owned().await.ok();
            let alive = probe_host(host, engine, use_icmp, &probe_ports).await;
            (host, alive)
        });
    }

    let mut live: HashSet<Ipv4Addr> = HashSet::new();
    while let Some(res) = set.join_next().await {
        if let Ok((host, true)) = res {
            live.insert(host);
        }
    }
    let mut live: Vec<Ipv4Addr> = live.into_iter().collect();
    live.sort_unstable();
    live
}

/// Probes a single host: ICMP when available, else TCP connect over `ports`,
/// stopping at the first success.
async fn probe_host(host: Ipv4Addr, engine: ProbeEngine, use_icmp: bool, ports: &[u16]) -> bool {
    if use_icmp {
        if let Ok(true) = engine.icmp_echo(host).await {
            return true;
        }
        // Fall through to TCP probing when ICMP fails or is blocked.
    }
    for &port in ports {
        if engine.tcp_connect(host, port).await {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn discovers_live_host_and_skips_dead() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        // Keep accepting so repeated connects succeed.
        let accept = tokio::spawn(async move {
            while let Ok((_sock, _peer)) = listener.accept().await {
                // drop the connection immediately; liveness is what matters
            }
        });

        let engine = ProbeEngine::new(Duration::from_millis(200));
        let live = discover_hosts_with_ports(
            &[Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)],
            engine,
            8,
            &[port],
        )
        .await;
        accept.abort();
        assert_eq!(live, vec![Ipv4Addr::LOCALHOST]);
    }

    #[tokio::test]
    async fn discovery_result_is_sorted() {
        let engine = ProbeEngine::new(Duration::from_millis(50));
        let hosts = vec![
            Ipv4Addr::new(127, 0, 0, 4),
            Ipv4Addr::new(127, 0, 0, 2),
            Ipv4Addr::new(127, 0, 0, 3),
        ];
        let live = discover_hosts(&hosts, engine, 8).await;
        let mut sorted = live.clone();
        sorted.sort_unstable();
        assert_eq!(live, sorted);
    }
}
