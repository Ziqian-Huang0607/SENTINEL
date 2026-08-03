//! Service fingerprinting: banner grabbing plus heuristic identification.
//!
//! [`identify`] is a pure function over `(port, banner bytes)` implementing
//! the heuristic table (SSH/OpenSSH, HTTP Server header, Redis, MySQL,
//! PostgreSQL, SMB, RDP, FTP, SMTP/Exim, Docker, Elasticsearch, MongoDB,
//! AJP). [`fingerprint_port`] performs the network side: connect, read any
//! server-initiated banner, then fall back to protocol probes (HTTP GET,
//! Redis PING) selected from port hints.

use crate::network::packet::ProbeEngine;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum banner bytes read per port.
const MAX_BANNER: usize = 512;
/// Banner bytes retained in the scan report (printable subset).
const REPORT_BANNER: usize = 256;

/// Banner-parse confidence tier (METHODOLOGY.md R4 instrumentation).
///
/// Serialized lowercase into scan.json's `banner_confidence` field so an
/// empirical precision table can be derived from the scan corpus.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Banner parsed and a product version extracted.
    High,
    /// Service identified from the banner, no usable version.
    Medium,
    /// Port-hint fallback or unidentified banner.
    #[default]
    Low,
}

/// Result of fingerprinting one open port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fingerprint {
    /// Canonical service name matched by the CVE cache, e.g. `openssh`.
    pub service: Option<String>,
    /// Detected product version, if any (normalized dotted form).
    pub version: Option<String>,
    /// Sanitized banner excerpt for the report.
    pub banner: Option<String>,
    /// Parse confidence (see [`Confidence`]); informational, never scored.
    pub confidence: Confidence,
}

impl Fingerprint {
    /// Sets `confidence` from the parse outcome: version ⇒ High, service
    /// without version ⇒ Medium, otherwise Low. Every constructor path in
    /// this module routes through this so the precision table is consistent.
    pub fn with_inferred_confidence(mut self) -> Self {
        self.confidence = match (&self.service, &self.version) {
            (Some(_), Some(_)) => Confidence::High,
            (Some(_), None) => Confidence::Medium,
            _ => Confidence::Low,
        };
        self
    }
}

/// Well-known service implied by port when no banner is available.
fn port_fallback_service(port: u16) -> Option<&'static str> {
    match port {
        22 => Some("ssh"),
        139 | 445 => Some("smb"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        6379 => Some("redis"),
        8009 => Some("ajp13"),
        9200 => Some("elasticsearch"),
        27017..=27019 => Some("mongodb"),
        2375 | 2376 => Some("docker"),
        _ => None,
    }
}

/// Normalizes a raw version token to a dotted numeric string.
/// `9.6p1` -> `9.6.1`, `4.90_1` -> `4.90.1`, `2.4.49` -> `2.4.49`.
/// Returns None when the token contains no digits.
pub fn normalize_version(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut last_was_sep = true;
    for ch in raw.chars() {
        if ch.is_ascii_digit() {
            out.push(ch);
            last_was_sep = false;
        } else if matches!(ch, '.' | 'p' | 'P' | '_') && !last_was_sep {
            out.push('.');
            last_was_sep = true;
        } else {
            break;
        }
    }
    let trimmed = out.trim_end_matches('.');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Extracts a printable, length-capped banner string from raw bytes.
pub fn sanitize_banner(data: &[u8]) -> Option<String> {
    let mut out = String::new();
    for &b in data {
        let ch = b as char;
        if ch == '\r' {
            continue;
        }
        if ch.is_ascii_graphic() || ch == ' ' || ch == '\n' || ch == '\t' {
            out.push(ch);
        } else {
            out.push('.');
        }
        if out.len() >= REPORT_BANNER {
            break;
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Pure identification of a service from its port and captured banner bytes.
pub fn identify(port: u16, data: &[u8]) -> Fingerprint {
    let text = String::from_utf8_lossy(data);
    let banner = sanitize_banner(data);

    // --- SSH -------------------------------------------------------------
    if let Some(line) = text.lines().next() {
        if line.starts_with("SSH-") {
            return identify_ssh(line, banner);
        }
    }

    // --- HTTP ------------------------------------------------------------
    if text.starts_with("HTTP/") {
        return identify_http(&text, banner);
    }

    // --- Redis (reply to PING) ------------------------------------------
    if text.starts_with("+PONG") || text.starts_with("-NOAUTH") || text.starts_with("-ERR") {
        return Fingerprint {
            service: Some("redis".to_string()),
            version: None,
            banner,
            confidence: Confidence::Low,
        }
        .with_inferred_confidence();
    }

    // --- MySQL handshake --------------------------------------------------
    if let Some(version) = mysql_handshake_version(data) {
        return Fingerprint {
            service: Some("mysql".to_string()),
            version: Some(version),
            banner,
            confidence: Confidence::Low,
        }
        .with_inferred_confidence();
    }

    // --- FTP / SMTP greeting ---------------------------------------------
    if text.starts_with("220 ") || text.starts_with("220-") {
        if let Some(fp) = identify_220(&text, banner.clone()) {
            return fp;
        }
    }

    // --- Port-based fallback ----------------------------------------------
    // Port-hint guesses are always Low confidence, even when the hint maps
    // to a service — no banner evidence exists (R4 precision semantics).
    Fingerprint {
        service: port_fallback_service(port).map(str::to_string),
        version: None,
        banner,
        confidence: Confidence::Low,
    }
}

/// Parses an SSH protocol banner: `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13`.
fn identify_ssh(line: &str, banner: Option<String>) -> Fingerprint {
    let proto_field = line.split_whitespace().next().unwrap_or(line);
    let implementation = proto_field
        .strip_prefix("SSH-")
        .and_then(|rest| rest.split_once('-'))
        .map(|(_, imp)| imp)
        .unwrap_or_default();

    let (service, version) = if let Some(ver) = implementation.strip_prefix("OpenSSH_") {
        ("openssh", normalize_version(ver))
    } else if let Some(ver) = implementation.strip_prefix("dropbear_") {
        ("dropbear", normalize_version(ver))
    } else {
        ("ssh", None)
    };
    Fingerprint {
        service: Some(service.to_string()),
        version,
        banner,
        confidence: Confidence::Low,
    }
    .with_inferred_confidence()
}

/// Maps an HTTP `Server` product token to a canonical service name.
fn http_product_service(product: &str) -> &'static str {
    let p = product.to_ascii_lowercase();
    if p.contains("apache-coyote") || p.contains("jetty") || p.contains("tomcat") {
        "java"
    } else if p.contains("apache") {
        "apache"
    } else if p.contains("nginx") {
        "nginx"
    } else if p.contains("microsoft-iis") {
        "iis"
    } else if p.contains("elasticsearch") {
        "elasticsearch"
    } else {
        "http"
    }
}

/// Identifies HTTP services from the status line, Server header and body.
fn identify_http(text: &str, banner: Option<String>) -> Fingerprint {
    // Docker Remote API: JSON body carrying an ApiVersion key.
    if text.contains("\"ApiVersion\"") {
        return Fingerprint {
            service: Some("docker".to_string()),
            version: json_string_field(text, "Version").and_then(|v| normalize_version(&v)),
            banner,
            confidence: Confidence::Low,
        }
        .with_inferred_confidence();
    }
    // Elasticsearch: tagline / cluster name + version.number.
    if text.contains("You Know, for Search") || text.contains("\"cluster_name\"") {
        if let Some(number) = json_string_field(text, "number") {
            return Fingerprint {
                service: Some("elasticsearch".to_string()),
                version: normalize_version(&number),
                banner,
                confidence: Confidence::Low,
            }
            .with_inferred_confidence();
        }
    }

    match header_value(text, "server") {
        Some(value) => {
            let mut parts = value.splitn(2, '/');
            let product = parts.next().unwrap_or_default().trim();
            let version = parts.next().and_then(normalize_version);
            Fingerprint {
                service: Some(http_product_service(product).to_string()),
                version,
                banner,
                confidence: Confidence::Low,
            }
            .with_inferred_confidence()
        }
        None => Fingerprint {
            service: Some("http".to_string()),
            version: None,
            banner,
            confidence: Confidence::Low,
        }
        .with_inferred_confidence(),
    }
}

/// Case-insensitive extraction of an HTTP header value from raw text.
fn header_value(text: &str, name: &str) -> Option<String> {
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case(name) {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Minimal `"key": "value"` string-field extractor for flat JSON snippets.
/// Robust to the truncated bodies typical of banner captures.
fn json_string_field(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = text.find(&needle)? + needle.len();
    let rest = text.get(start..)?;
    let rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == ':');
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Validates a MySQL initial handshake packet and extracts the server
/// version. Layout: 3-byte length, 1-byte seq, protocol 0x0a, NUL-terminated
/// version string.
fn mysql_handshake_version(data: &[u8]) -> Option<String> {
    if data.len() < 7 {
        return None;
    }
    let declared = usize::from(data[0]) | usize::from(data[1]) << 8 | usize::from(data[2]) << 16;
    if declared + 4 > data.len() || data[4] != 0x0a {
        return None;
    }
    let version_bytes = &data[5..];
    let end = version_bytes.iter().position(|&b| b == 0)?;
    let version = std::str::from_utf8(&version_bytes[..end]).ok()?;
    if version.len() < 3 || !version.chars().next()?.is_ascii_digit() {
        return None;
    }
    normalize_version(version)
}

/// Finds the version token following a product keyword in a greeting,
/// e.g. `... Exim 4.90_1 ...` -> `4.90.1`.
fn version_after_keyword(lower: &str, keyword: &str) -> Option<String> {
    let idx = lower.find(keyword)?;
    let rest = lower.get(idx + keyword.len()..)?;
    let token = rest.split_whitespace().next()?;
    normalize_version(token)
}

/// Identifies FTP vs SMTP software from a `220` greeting line.
fn identify_220(text: &str, banner: Option<String>) -> Option<Fingerprint> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("exim") {
        return Some(Fingerprint {
            service: Some("exim".to_string()),
            version: version_after_keyword(&lower, "exim"),
            banner,
            confidence: Confidence::Low,
        }
        .with_inferred_confidence());
    }
    if lower.contains("smtp") || lower.contains("esmtp") || lower.contains("postfix") {
        return Some(Fingerprint {
            service: Some("smtp".to_string()),
            version: None,
            banner,
            confidence: Confidence::Low,
        }
        .with_inferred_confidence());
    }
    if lower.contains("vsftpd") {
        return Some(Fingerprint {
            service: Some("vsftpd".to_string()),
            version: version_after_keyword(&lower, "vsftpd"),
            banner,
            confidence: Confidence::Low,
        }
        .with_inferred_confidence());
    }
    if lower.contains("proftpd") {
        return Some(Fingerprint {
            service: Some("proftpd".to_string()),
            version: version_after_keyword(&lower, "proftpd"),
            banner,
            confidence: Confidence::Low,
        }
        .with_inferred_confidence());
    }
    Some(Fingerprint {
        service: Some("ftp".to_string()),
        version: None,
        banner,
        confidence: Confidence::Low,
    }
    .with_inferred_confidence())
}

/// Picks an application-layer probe payload for a port, if any.
fn probe_payload(port: u16) -> Option<&'static [u8]> {
    match port {
        6379 => Some(b"PING\r\n"),
        9200 => Some(b"GET / HTTP/1.0\r\nHost: sentinel\r\n\r\n"),
        2375 | 2376 => Some(b"GET /version HTTP/1.0\r\nHost: sentinel\r\n\r\n"),
        80 | 81 | 3000 | 5000 | 5601 | 8000 | 8008 | 8080 | 8081 | 8088 | 8090 | 8180 | 8443
        | 8888 | 9000 | 9090 | 10000 => Some(b"GET / HTTP/1.0\r\nHost: sentinel\r\n\r\n"),
        _ => None,
    }
}

/// Generic probes tried on unknown ports that stay silent, in order.
const GENERIC_PROBES: [&[u8]; 2] = [b"GET / HTTP/1.0\r\nHost: sentinel\r\n\r\n", b"PING\r\n"];

/// Reads up to `MAX_BANNER` bytes with a deadline, returning whatever
/// arrived (possibly empty).
async fn read_banner(stream: &mut tokio::net::TcpStream, wait: Duration) -> Vec<u8> {
    let mut buf = vec![0u8; MAX_BANNER];
    match tokio::time::timeout(wait, stream.read(&mut buf)).await {
        Ok(Ok(n)) => buf.truncate(n),
        _ => buf.clear(),
    }
    buf
}

/// Fingerprints one open port on `ip`: grabs a banner and runs [`identify`].
pub async fn fingerprint_port(ip: Ipv4Addr, port: u16, engine: ProbeEngine) -> Fingerprint {
    let wait = engine.timeout();
    let Ok(mut stream) = engine.tcp_open(ip, port).await else {
        return Fingerprint::default();
    };

    // 1. Server-initiated banner (SSH, FTP, SMTP, MySQL...).
    let mut data = read_banner(&mut stream, wait).await;

    // 2. Port-hinted probe, then generic probes for silent unknown ports.
    if data.is_empty() {
        if let Some(payload) = probe_payload(port) {
            if stream.write_all(payload).await.is_ok() {
                data = read_banner(&mut stream, wait).await;
            }
        }
    }
    if data.is_empty() && probe_payload(port).is_none() {
        for payload in GENERIC_PROBES {
            if stream.write_all(payload).await.is_err() {
                break;
            }
            data = read_banner(&mut stream, wait).await;
            if !data.is_empty() {
                break;
            }
        }
    }

    identify(port, &data)
}

/// Guesses an OS family from the set of open ports (banner-free heuristic).
pub fn guess_os(open_ports: &[u16]) -> Option<String> {
    let has = |p: u16| open_ports.contains(&p);
    if has(445) || has(3389) || has(135) {
        Some("Windows (port heuristic)".to_string())
    } else if has(22) || has(111) || has(515) {
        Some("Linux/Unix (port heuristic)".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openssh_banner() {
        let fp = identify(22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n");
        assert_eq!(fp.service.as_deref(), Some("openssh"));
        assert_eq!(fp.version.as_deref(), Some("9.6.1"));
        assert!(fp.banner.expect("banner").contains("OpenSSH"));
    }

    #[test]
    fn parses_dropbear_banner() {
        let fp = identify(22, b"SSH-2.0-dropbear_2022.83\r\n");
        assert_eq!(fp.service.as_deref(), Some("dropbear"));
        assert_eq!(fp.version.as_deref(), Some("2022.83"));
    }

    #[test]
    fn parses_http_server_headers() {
        let nginx = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 2\r\n\r\nhi";
        let fp = identify(80, nginx);
        assert_eq!(fp.service.as_deref(), Some("nginx"));
        assert_eq!(fp.version.as_deref(), Some("1.24.0"));

        let apache = b"HTTP/1.0 404 Not Found\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n";
        let fp = identify(80, apache);
        assert_eq!(fp.service.as_deref(), Some("apache"));
        assert_eq!(fp.version.as_deref(), Some("2.4.49"));

        let coyote = b"HTTP/1.1 200\r\nServer: Apache-Coyote/1.1\r\n\r\n";
        let fp = identify(8080, coyote);
        assert_eq!(fp.service.as_deref(), Some("java"));
    }

    #[test]
    fn parses_redis_replies() {
        let fp = identify(6379, b"-NOAUTH Authentication required.\r\n");
        assert_eq!(fp.service.as_deref(), Some("redis"));
        assert_eq!(fp.version, None);
        assert_eq!(
            fp.banner.as_deref(),
            Some("-NOAUTH Authentication required.")
        );

        let pong = identify(6379, b"+PONG\r\n");
        assert_eq!(pong.service.as_deref(), Some("redis"));
    }

    #[test]
    fn parses_mysql_handshake() {
        // Realistic handshake: len, seq 0, protocol 10, version "8.0.36".
        let version = b"8.0.36";
        let mut pkt = vec![0u8; 3];
        // MySQL length field counts payload AFTER the 4-byte header:
        // protocol(1) + version + NUL(1) + filler(25).
        let body_len = (1 + version.len() + 1 + 25) as u32;
        pkt[0] = (body_len & 0xff) as u8;
        pkt[1] = ((body_len >> 8) & 0xff) as u8;
        pkt[2] = ((body_len >> 16) & 0xff) as u8;
        pkt.push(0); // seq
        pkt.push(0x0a); // protocol
        pkt.extend_from_slice(version);
        pkt.push(0); // NUL
        pkt.extend_from_slice(&[0x55u8; 25]); // auth data filler

        let fp = identify(3306, &pkt);
        assert_eq!(fp.service.as_deref(), Some("mysql"));
        assert_eq!(fp.version.as_deref(), Some("8.0.36"));
    }

    #[test]
    fn short_garbage_falls_back_to_port_hint() {
        let fp = identify(3306, &[0x01, 0x02, 0x03]);
        assert_eq!(fp.service.as_deref(), Some("mysql"));
        assert_eq!(fp.version, None);
    }

    #[test]
    fn confidence_tracks_parse_strength() {
        // Banner + version → High.
        let fp = identify(22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n");
        assert_eq!(fp.confidence, Confidence::High);
        // Banner identifies service, no version → Medium.
        let fp = identify(6379, b"-NOAUTH Authentication required.\r\n");
        assert_eq!(fp.service.as_deref(), Some("redis"));
        assert_eq!(fp.confidence, Confidence::Medium);
        // HTTP without Server header → Medium (service from status line).
        let fp = identify(8080, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(fp.confidence, Confidence::Medium);
        // Port-hint fallback → Low even when a service is guessed.
        let fp = identify(3306, &[0x01, 0x02, 0x03]);
        assert_eq!(fp.confidence, Confidence::Low);
        let fp = identify(445, b"");
        assert_eq!(fp.confidence, Confidence::Low);
        // Unidentified, no hint → Low.
        let fp = identify(49999, b"hello");
        assert_eq!(fp.service, None);
        assert_eq!(fp.confidence, Confidence::Low);
    }

    #[test]
    fn confidence_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&Confidence::High).expect("ser"),
            "\"high\""
        );
        assert_eq!(
            serde_json::to_string(&Confidence::Medium).expect("ser"),
            "\"medium\""
        );
        assert_eq!(
            serde_json::to_string(&Confidence::Low).expect("ser"),
            "\"low\""
        );
    }

    #[test]
    fn port_fallbacks_cover_infra_services() {
        assert_eq!(identify(445, b"").service.as_deref(), Some("smb"));
        assert_eq!(identify(3389, b"").service.as_deref(), Some("rdp"));
        assert_eq!(identify(5432, b"").service.as_deref(), Some("postgresql"));
        assert_eq!(identify(27017, b"").service.as_deref(), Some("mongodb"));
        assert_eq!(
            identify(9200, b"").service.as_deref(),
            Some("elasticsearch")
        );
        assert_eq!(identify(2375, b"").service.as_deref(), Some("docker"));
        assert_eq!(identify(8009, b"").service.as_deref(), Some("ajp13"));
    }

    #[test]
    fn parses_exim_and_ftp_greetings() {
        let fp = identify(
            25,
            b"220 mail.example.com ESMTP Exim 4.90_1 Tue, 01 Jan 2019\r\n",
        );
        assert_eq!(fp.service.as_deref(), Some("exim"));
        assert_eq!(fp.version.as_deref(), Some("4.90.1"));

        let fp = identify(21, b"220 (vsFTPd 2.3.4)\r\n");
        assert_eq!(fp.service.as_deref(), Some("vsftpd"));
        assert_eq!(fp.version.as_deref(), Some("2.3.4"));

        let fp = identify(21, b"220 ProFTPD 1.3.5 Server (ftp) [::ffff:10.0.0.1]\r\n");
        assert_eq!(fp.service.as_deref(), Some("proftpd"));
        assert_eq!(fp.version.as_deref(), Some("1.3.5"));
    }

    #[test]
    fn parses_elasticsearch_and_docker_json() {
        let es = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"n1\",\"cluster_name\":\"es\",\"version\":{\"number\":\"1.4.2\",\"lucene_version\":\"4.10\"},\"tagline\":\"You Know, for Search\"}";
        let fp = identify(9200, es);
        assert_eq!(fp.service.as_deref(), Some("elasticsearch"));
        assert_eq!(fp.version.as_deref(), Some("1.4.2"));

        let docker = b"HTTP/1.1 200 OK\r\n\r\n{\"Version\":\"18.06.1-ce\",\"ApiVersion\":\"1.38\",\"Os\":\"linux\"}";
        let fp = identify(2375, docker);
        assert_eq!(fp.service.as_deref(), Some("docker"));
        assert_eq!(fp.version.as_deref(), Some("18.06.1"));
    }

    #[test]
    fn normalizes_versions() {
        assert_eq!(normalize_version("9.6p1").as_deref(), Some("9.6.1"));
        assert_eq!(normalize_version("2.4.49").as_deref(), Some("2.4.49"));
        assert_eq!(
            normalize_version("8.0.36-0ubuntu0.22.04.1").as_deref(),
            Some("8.0.36")
        );
        assert_eq!(normalize_version("4.90_1").as_deref(), Some("4.90.1"));
        assert_eq!(normalize_version("abc"), None);
    }

    #[test]
    fn sanitizes_binary_banners() {
        let banner = sanitize_banner(b"SSH-2.0-x\r\n\x00\xffgarbage").expect("some text");
        assert!(banner.starts_with("SSH-2.0-x"));
        assert!(banner.len() <= REPORT_BANNER);
        assert_eq!(sanitize_banner(b""), None);
    }

    #[test]
    fn os_guess_heuristics() {
        assert_eq!(
            guess_os(&[445, 139]).as_deref(),
            Some("Windows (port heuristic)")
        );
        assert_eq!(
            guess_os(&[22, 80]).as_deref(),
            Some("Linux/Unix (port heuristic)")
        );
        assert_eq!(guess_os(&[9200]), None);
    }
}
