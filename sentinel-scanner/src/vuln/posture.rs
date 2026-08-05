//! Posture findings: exposures that carry real risk without any CVE match.
//!
//! A signature DB can only fire on known CVEs — an unauthenticated router
//! admin panel or a legacy LPD port is not a CVE, yet "0 matches" must never
//! read as "no risk". Posture findings close that gap: they are classified
//! from probe evidence (HTTP status codes, identified services) and scored
//! through the SAME deterministic formula as CVE findings with EPSS = 0
//! (no exploitation-probability data for a configuration exposure).
//!
//! Severities are conservative pseudo-CVSS constants per class — see
//! METHODOLOGY.md Ch.8 R8 for the rationale.

use std::net::Ipv4Addr;

use crate::network::fingerprint::Fingerprint;
use crate::network::http_probe::{AuthState, HttpProbe};
use crate::output::json::PostureReport;

/// Unauthenticated web admin on a gateway/router (.1 / .254 host).
pub const SEV_UNAUTH_WEB_GATEWAY: f64 = 7.5;
/// Unauthenticated web interface on a regular host.
pub const SEV_UNAUTH_WEB: f64 = 6.5;
/// Unauthenticated IPP/CUPS printing interface (RCE history).
pub const SEV_UNAUTH_IPP: f64 = 6.5;
/// Legacy LPD print service (515) — cleartext, unauthenticated by design.
pub const SEV_LEGACY_LPD: f64 = 5.3;
/// Raw JetDirect-style printing port (9100) — unauthenticated job submission.
pub const SEV_RAW_PRINTER: f64 = 4.3;
/// Cleartext credentials protocol (telnet, ftp without TLS).
pub const SEV_CLEARTEXT: f64 = 6.5;
/// Unauthenticated datastore/admin service (redis, mongodb, elasticsearch,
/// memcached, docker API) — matched by service identity even versionless.
pub const SEV_UNAUTH_DATASTORE: f64 = 7.5;

/// Datastores that must never answer without authentication.
const DATASTORE_SERVICES: &[&str] = &["redis", "mongodb", "elasticsearch", "memcached", "docker"];

/// Builds the evidence string recorded on a posture finding.
fn evidence(fp: &Fingerprint, probe: Option<&HttpProbe>) -> String {
    let mut parts = Vec::new();
    if let Some(p) = probe {
        parts.push(format!("GET / -> {}", p.status));
        if let Some(s) = &p.server {
            parts.push(format!("Server: {s}"));
        }
        if let Some(t) = &p.title {
            parts.push(format!("Title: \"{t}\""));
        }
    }
    if let Some(b) = &fp.banner {
        parts.push(format!("banner: {b}"));
    }
    if parts.is_empty() {
        parts.push("port open, no banner returned".to_string());
    }
    parts.join("; ")
}

/// True for hosts that look like a network gateway (last octet .1 or .254).
/// Loopback is never a gateway — 127.0.0.1 ends in .1 by definition.
fn is_gateway(ip: &Ipv4Addr) -> bool {
    if ip.is_loopback() {
        return false;
    }
    let last = ip.octets()[3];
    last == 1 || last == 254
}

/// Classifies one open port into zero or more posture findings.
///
/// * `ip`/`port` — the open port under consideration.
/// * `fp` — banner fingerprint (may be empty).
/// * `probe` — HTTP probe result when the port was probed.
pub fn classify(
    ip: &Ipv4Addr,
    port: u16,
    fp: &Fingerprint,
    probe: Option<&HttpProbe>,
) -> Vec<PostureReport> {
    let mut out = Vec::new();
    let host = ip.to_string();
    let service = fp.service.as_deref().unwrap_or("");

    // 1. Proven-unauthenticated web interfaces (HTTP 200 / non-login 30x).
    if let Some(p) = probe {
        if p.auth == AuthState::Unauth {
            let (id, severity, title) = if service == "cups" || service == "ipp" || port == 631 {
                (
                    "POSTURE-UNAUTH-IPP",
                    SEV_UNAUTH_IPP,
                    "IPP/CUPS interface accepts unauthenticated requests",
                )
            } else if is_gateway(ip) {
                (
                    "POSTURE-UNAUTH-WEB-GATEWAY",
                    SEV_UNAUTH_WEB_GATEWAY,
                    "Gateway/router web admin reachable without authentication",
                )
            } else {
                (
                    "POSTURE-UNAUTH-WEB",
                    SEV_UNAUTH_WEB,
                    "Web interface reachable without authentication",
                )
            };
            out.push(PostureReport {
                id: id.to_string(),
                host: host.clone(),
                port,
                severity,
                title: title.to_string(),
                evidence: evidence(fp, probe),
            });
        }
    }

    // 2. Legacy / risky services by port or identity (no probe needed).
    let legacy: Option<(&str, f64, &str)> = if port == 515 {
        Some((
            "POSTURE-LEGACY-LPD",
            SEV_LEGACY_LPD,
            "LPD print service exposed (legacy cleartext protocol)",
        ))
    } else if port == 9100 {
        Some((
            "POSTURE-RAW-PRINTER",
            SEV_RAW_PRINTER,
            "Raw printing port accepts unauthenticated job submission",
        ))
    } else if service == "telnet" || port == 23 {
        Some((
            "POSTURE-CLEARTEXT",
            SEV_CLEARTEXT,
            "Telnet exposes cleartext credentials and session traffic",
        ))
    } else if service == "ftp" && port == 21 {
        Some((
            "POSTURE-CLEARTEXT",
            SEV_CLEARTEXT,
            "FTP exposes cleartext credentials and transfers",
        ))
    } else if DATASTORE_SERVICES.contains(&service) {
        Some((
            "POSTURE-UNAUTH-DATASTORE",
            SEV_UNAUTH_DATASTORE,
            "Datastore/admin service answered without authentication",
        ))
    } else {
        None
    };
    if let Some((id, severity, title)) = legacy {
        out.push(PostureReport {
            id: id.to_string(),
            host,
            port,
            severity,
            title: title.to_string(),
            evidence: evidence(fp, probe),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::http_probe::AuthState;

    fn fp(service: Option<&str>) -> Fingerprint {
        Fingerprint {
            service: service.map(str::to_string),
            ..Default::default()
        }
    }

    fn probe(status: u16, auth: AuthState) -> HttpProbe {
        HttpProbe {
            status,
            server: None,
            title: None,
            auth,
        }
    }

    #[test]
    fn unauth_200_on_gateway_is_critical_class() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let findings = classify(
            &ip,
            80,
            &fp(Some("http")),
            Some(&probe(200, AuthState::Unauth)),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "POSTURE-UNAUTH-WEB-GATEWAY");
        assert_eq!(findings[0].severity, SEV_UNAUTH_WEB_GATEWAY);
    }

    #[test]
    fn loopback_is_never_a_gateway() {
        let ip = Ipv4Addr::LOCALHOST; // 127.0.0.1 ends in .1 but is not a router
        let findings = classify(
            &ip,
            80,
            &fp(Some("http")),
            Some(&probe(200, AuthState::Unauth)),
        );
        assert_eq!(findings[0].id, "POSTURE-UNAUTH-WEB");
    }

    #[test]
    fn unauth_200_on_regular_host_is_web_class() {
        let ip = Ipv4Addr::new(192, 168, 1, 9);
        let findings = classify(
            &ip,
            80,
            &fp(Some("nginx")),
            Some(&probe(200, AuthState::Unauth)),
        );
        assert_eq!(findings[0].id, "POSTURE-UNAUTH-WEB");
    }

    #[test]
    fn cups_port_631_maps_to_ipp_class() {
        let ip = Ipv4Addr::new(192, 168, 1, 102);
        let findings = classify(
            &ip,
            631,
            &fp(Some("cups")),
            Some(&probe(200, AuthState::Unauth)),
        );
        assert_eq!(findings[0].id, "POSTURE-UNAUTH-IPP");
    }

    #[test]
    fn gated_interfaces_produce_no_web_finding() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let findings = classify(
            &ip,
            80,
            &fp(Some("http")),
            Some(&probe(401, AuthState::Gated)),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn lpd_and_raw_printer_ports_flag_without_probe() {
        let ip = Ipv4Addr::new(192, 168, 1, 102);
        let lpd = classify(&ip, 515, &fp(None), None);
        assert_eq!(lpd[0].id, "POSTURE-LEGACY-LPD");
        let raw = classify(&ip, 9100, &fp(None), None);
        assert_eq!(raw[0].id, "POSTURE-RAW-PRINTER");
    }

    #[test]
    fn versionless_datastore_still_flags() {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let findings = classify(&ip, 6379, &fp(Some("redis")), None);
        assert_eq!(findings[0].id, "POSTURE-UNAUTH-DATASTORE");
    }

    #[test]
    fn plain_https_service_port_443_is_quiet() {
        let ip = Ipv4Addr::new(10, 0, 0, 6);
        assert!(classify(&ip, 443, &fp(Some("https")), None).is_empty());
    }
}
