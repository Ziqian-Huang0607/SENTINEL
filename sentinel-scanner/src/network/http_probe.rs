//! Lightweight HTTP/1.x probe for web-ish ports.
//!
//! One `GET /` per candidate port (what any browser would do) yields three
//! signals the banner grabber cannot: the `Server` header (product + version
//! for CVE matching), the HTTP status code (authentication evidence), and
//! the page `<title>` (device/application identification). Findings from
//! this probe feed the posture classifier (crate::vuln::posture).

use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::network::packet::ProbeEngine;

/// Maximum bytes read from an HTTP response (status line + headers + start
/// of body is all we need).
const MAX_RESPONSE: usize = 16 * 1024;

/// Well-known HTTP ports probed even when the banner grabber saw nothing.
const WEB_PORTS: &[u16] = &[80, 8000, 8008, 8080, 8081, 8088, 8888, 591, 631];

/// Services whose fingerprint already implies HTTP semantics.
const HTTP_SERVICES: &[&str] = &["http", "nginx", "apache", "iis", "httpd", "cups", "ipp"];

/// Authentication state inferred from the response status line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// Resource served without any credential challenge.
    Unauth,
    /// 401/403, or a redirect to a login/auth page.
    Gated,
    /// Anything else (5xx, odd codes, redirect loops we cannot classify).
    Unknown,
}

/// Parsed result of one HTTP probe.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpProbe {
    /// Numeric status code (e.g. 200).
    pub status: u16,
    /// Raw `Server` header value, if present.
    pub server: Option<String>,
    /// Page `<title>` contents (sanitized, truncated), if present.
    pub title: Option<String>,
    /// Authentication state derived from status + Location.
    pub auth: AuthState,
}

impl HttpProbe {
    /// Product + version parsed from the `Server` header's first
    /// `product/x.y` token, e.g. `nginx/1.18.0` → `("nginx", "1.18.0")`.
    /// Product is lowercased; `microsoft-iis` normalizes to `iis` so the
    /// CVE cache service name matches.
    pub fn server_product_version(&self) -> Option<(String, String)> {
        let server = self.server.as_deref()?;
        for token in server.split_whitespace() {
            let (product, version) = token.split_once('/')?;
            if version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                let dotted: String = version
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                let dotted = dotted.trim_end_matches('.').to_string();
                if dotted.is_empty() {
                    continue;
                }
                let product = product.to_ascii_lowercase();
                let product = if product == "microsoft-iis" {
                    "iis"
                } else {
                    &product
                };
                return Some((product.to_string(), dotted));
            }
        }
        None
    }
}

/// True when a port is worth an HTTP probe: well-known web port, an
/// HTTP-ish identified service, or a banner that already speaks HTTP.
pub fn should_probe(port: u16, service: Option<&str>, banner: Option<&str>) -> bool {
    if WEB_PORTS.contains(&port) {
        return true;
    }
    if let Some(svc) = service {
        if HTTP_SERVICES.contains(&svc) {
            return true;
        }
    }
    banner.is_some_and(|b| b.starts_with("HTTP/"))
}

/// Probes `ip:port` with a single `GET /` request. Returns `None` when the
/// service does not answer with a parseable HTTP status line.
pub async fn probe_http(ip: Ipv4Addr, port: u16, engine: ProbeEngine) -> Option<HttpProbe> {
    let wait = engine.timeout();
    let mut stream = engine.tcp_open(ip, port).await.ok()?;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: sentinel/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.ok()?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + wait;
    while buf.len() < MAX_RESPONSE {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) | Err(_) => break,
        }
        // Headers + some body is enough; stop early once the title tag closes.
        if buf.windows(b"</title>".len()).any(|w| w == b"</title>") {
            break;
        }
    }
    parse_response(&buf)
}

/// Parses status line, headers and `<title>` from a raw HTTP response.
pub fn parse_response(bytes: &[u8]) -> Option<HttpProbe> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?;
    if !status_line.starts_with("HTTP/") {
        return None;
    }
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut server = None;
    let mut location = None;
    for line in lines.by_ref() {
        if line.is_empty() {
            break; // end of headers
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            match name.as_str() {
                "server" => server = Some(value.to_string()),
                "location" => location = Some(value.to_string()),
                _ => {}
            }
        }
    }

    let title = extract_title(&text);

    let auth = match status {
        200 => AuthState::Unauth,
        401 | 403 => AuthState::Gated,
        301 | 302 | 303 | 307 | 308 => match location.as_deref() {
            Some(loc) if redirects_to_login(loc) => AuthState::Gated,
            Some(_) => AuthState::Unauth, // redirect straight into the app
            None => AuthState::Unknown,
        },
        _ => AuthState::Unknown,
    };

    Some(HttpProbe {
        status,
        server,
        title,
        auth,
    })
}

/// `<title>...</title>` contents, sanitized and truncated to 128 chars.
fn extract_title(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let start = lower.find("<title>")? + "<title>".len();
    let end = lower[start..].find("</title>").map(|i| start + i)?;
    let raw = &text[start..end.min(text.len())];
    let clean: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let clean = clean.chars().take(128).collect::<String>();
    (!clean.is_empty()).then_some(clean)
}

/// True when a redirect target looks like a login/auth page.
fn redirects_to_login(location: &str) -> bool {
    let loc = location.to_ascii_lowercase();
    ["login", "logon", "signin", "auth", "passwort"]
        .iter()
        .any(|k| loc.contains(k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_response_with_version_and_title() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><head><title>Welcome to nginx!</title></head></html>";
        let p = parse_response(raw).unwrap();
        assert_eq!(p.status, 200);
        assert_eq!(p.auth, AuthState::Unauth);
        assert_eq!(
            p.server_product_version(),
            Some(("nginx".into(), "1.18.0".into()))
        );
        assert_eq!(p.title.as_deref(), Some("Welcome to nginx!"));
    }

    #[test]
    fn redirect_to_login_is_gated_redirect_elsewhere_is_unauth() {
        let gated =
            parse_response(b"HTTP/1.1 302 Found\r\nLocation: /ui/login.html\r\n\r\n").unwrap();
        assert_eq!(gated.auth, AuthState::Gated);
        let unauth = parse_response(b"HTTP/1.1 302 Found\r\nLocation: /admin\r\n\r\n").unwrap();
        assert_eq!(unauth.auth, AuthState::Unauth);
    }

    #[test]
    fn challenge_codes_are_gated() {
        for code in [401, 403] {
            let raw = format!("HTTP/1.1 {code} Nope\r\nWWW-Authenticate: Basic\r\n\r\n");
            assert_eq!(
                parse_response(raw.as_bytes()).unwrap().auth,
                AuthState::Gated
            );
        }
    }

    #[test]
    fn cups_server_header_yields_version() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: CUPS/2.4 IPP/2.1\r\n\r\n";
        let p = parse_response(raw).unwrap();
        assert_eq!(
            p.server_product_version(),
            Some(("cups".into(), "2.4".into()))
        );
    }

    #[test]
    fn iis_normalizes_to_cache_service_name() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n";
        let p = parse_response(raw).unwrap();
        assert_eq!(
            p.server_product_version(),
            Some(("iis".into(), "10.0".into()))
        );
    }

    #[test]
    fn non_http_garbage_is_none() {
        assert!(parse_response(b"+PONG\r\n").is_none());
        assert!(parse_response(b"").is_none());
    }

    #[test]
    fn should_probe_covers_web_ports_and_http_services() {
        assert!(should_probe(8080, None, None));
        assert!(should_probe(631, None, None));
        assert!(should_probe(9999, Some("nginx"), None));
        assert!(should_probe(9999, None, Some("HTTP/1.1 200 OK")));
        assert!(!should_probe(22, Some("openssh"), None));
    }
}
