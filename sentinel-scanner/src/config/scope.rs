//! Scan scope parsing and validation.
//!
//! Accepts a single target expression made of comma-separated tokens, where
//! each token is either an IPv4 CIDR block (`10.0.0.0/24`) or a single IPv4
//! address (`10.0.0.7`). The enumerated host list is capped at
//! [`MAX_SCOPE_HOSTS`]. By default only RFC1918 private, loopback and
//! link-local addresses are accepted; anything else requires the operator to
//! pass `--allow-public`.

use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::str::FromStr;
use thiserror::Error;

/// Maximum number of hosts a single scan may enumerate.
pub const MAX_SCOPE_HOSTS: usize = 4096;

/// Errors produced while parsing or validating a scan scope.
#[derive(Debug, Error)]
pub enum ScopeError {
    /// A token was neither a valid IPv4 address nor a valid CIDR block.
    #[error("invalid target token '{0}': expected an IPv4 address or CIDR block")]
    InvalidToken(String),
    /// The scope expanded to more than [`MAX_SCOPE_HOSTS`] hosts.
    #[error("scope enumerates {0} hosts which exceeds the cap of {MAX_SCOPE_HOSTS}")]
    TooManyHosts(usize),
    /// The scope contained no usable hosts.
    #[error("scope is empty: no hosts to scan")]
    Empty,
    /// A host outside private/loopback/link-local space was found and
    /// `--allow-public` was not set.
    #[error("target '{0}' is not a private (RFC1918), loopback or link-local address; pass --allow-public to scan public space")]
    NonPrivateTarget(Ipv4Addr),
}

/// A validated scan scope: the original expression plus the enumerated hosts.
#[derive(Debug, Clone)]
pub struct Scope {
    /// The raw target expression as supplied by the operator.
    pub raw: String,
    /// Enumerated, deduplicated target hosts (sorted).
    pub hosts: Vec<Ipv4Addr>,
    /// Whether public address space was explicitly allowed.
    pub allow_public: bool,
}

/// Human/CLI-facing summary of a parsed scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSummary {
    /// The raw target expression.
    pub target: String,
    /// Number of enumerated hosts.
    pub host_count: usize,
    /// First enumerated host, if any.
    pub first: Option<Ipv4Addr>,
    /// Last enumerated host, if any.
    pub last: Option<Ipv4Addr>,
    /// True when every host sits in private/loopback/link-local space.
    pub all_private: bool,
}

/// Returns true for RFC1918 private, loopback and link-local IPv4 addresses.
pub fn is_private_or_local(ip: &Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

impl Scope {
    /// Parses `input` (comma-separated CIDR/IPv4 tokens) into a validated
    /// scope. When `allow_public` is false, any host outside
    /// private/loopback/link-local space is rejected.
    pub fn parse(input: &str, allow_public: bool) -> Result<Scope, ScopeError> {
        let mut hosts: Vec<Ipv4Addr> = Vec::new();
        for token in input.split(',').map(str::trim) {
            if token.is_empty() {
                continue;
            }
            let token_hosts = parse_token(token)?;
            hosts.extend(token_hosts);
        }
        hosts.sort_unstable();
        hosts.dedup();

        if hosts.is_empty() {
            return Err(ScopeError::Empty);
        }
        if hosts.len() > MAX_SCOPE_HOSTS {
            return Err(ScopeError::TooManyHosts(hosts.len()));
        }
        if !allow_public {
            if let Some(bad) = hosts.iter().find(|ip| !is_private_or_local(ip)) {
                return Err(ScopeError::NonPrivateTarget(*bad));
            }
        }
        Ok(Scope {
            raw: input.to_string(),
            hosts,
            allow_public,
        })
    }

    /// Builds a summary describing this scope for display to the operator.
    pub fn summary(&self) -> ScopeSummary {
        ScopeSummary {
            target: self.raw.clone(),
            host_count: self.hosts.len(),
            first: self.hosts.first().copied(),
            last: self.hosts.last().copied(),
            all_private: self.hosts.iter().all(is_private_or_local),
        }
    }
}

/// Parses one scope token: either `a.b.c.d/prefix` or a bare IPv4 address.
fn parse_token(token: &str) -> Result<Vec<Ipv4Addr>, ScopeError> {
    if let Ok(net) = Ipv4Net::from_str(token) {
        // ipnet's `hosts()` handles /31 and /32 correctly (yields both / the
        // single address respectively) and excludes network+broadcast for
        // wider prefixes.
        return Ok(net.hosts().collect());
    }
    if let Ok(ip) = Ipv4Addr::from_str(token) {
        return Ok(vec![ip]);
    }
    Err(ScopeError::InvalidToken(token.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_private_ip() {
        let scope = Scope::parse("192.168.1.45", false).expect("valid scope");
        assert_eq!(scope.hosts, vec![Ipv4Addr::new(192, 168, 1, 45)]);
        let summary = scope.summary();
        assert_eq!(summary.host_count, 1);
        assert!(summary.all_private);
    }

    #[test]
    fn parses_cidr_24_excluding_network_and_broadcast() {
        let scope = Scope::parse("192.168.1.0/24", false).expect("valid scope");
        assert_eq!(scope.hosts.len(), 254);
        assert_eq!(scope.hosts.first(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(scope.hosts.last(), Some(&Ipv4Addr::new(192, 168, 1, 254)));
    }

    #[test]
    fn parses_cidr_32_loopback() {
        let scope = Scope::parse("127.0.0.1/32", false).expect("valid scope");
        assert_eq!(scope.hosts, vec![Ipv4Addr::new(127, 0, 0, 1)]);
    }

    #[test]
    fn parses_comma_list_and_dedups() {
        let scope = Scope::parse("10.0.0.1, 10.0.0.2/32,10.0.0.1", false).expect("valid scope");
        assert_eq!(
            scope.hosts,
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
    }

    #[test]
    fn rejects_public_ip_without_allow_public() {
        let err = Scope::parse("8.8.8.8", false).expect_err("must reject public ip");
        assert!(matches!(err, ScopeError::NonPrivateTarget(_)));
    }

    #[test]
    fn rejects_public_cidr_without_allow_public() {
        let err = Scope::parse("203.0.113.0/30", false).expect_err("must reject");
        assert!(matches!(err, ScopeError::NonPrivateTarget(_)));
    }

    #[test]
    fn accepts_public_with_allow_public() {
        let scope = Scope::parse("8.8.8.8", true).expect("allowed with flag");
        assert_eq!(scope.hosts, vec![Ipv4Addr::new(8, 8, 8, 8)]);
        assert!(!scope.summary().all_private);
    }

    #[test]
    fn rejects_mixed_scope_containing_one_public_host() {
        let err =
            Scope::parse("10.0.0.1,1.2.3.4", false).expect_err("one bad host fails the scope");
        assert!(matches!(err, ScopeError::NonPrivateTarget(_)));
    }

    #[test]
    fn rejects_invalid_token() {
        let err = Scope::parse("not-an-ip", false).expect_err("invalid token");
        assert!(matches!(err, ScopeError::InvalidToken(_)));
    }

    #[test]
    fn rejects_empty_scope() {
        let err = Scope::parse(" , ,", false).expect_err("empty scope");
        assert!(matches!(err, ScopeError::Empty));
    }

    #[test]
    fn enforces_host_cap() {
        // 10.0.0.0/22 has 1022 hosts, two overlapping /16s exceed the cap.
        let err = Scope::parse("10.0.0.0/16", false).expect_err("over cap");
        assert!(matches!(err, ScopeError::TooManyHosts(_)));
    }

    #[test]
    fn accepts_scope_at_cap_boundary() {
        // /20 gives 4094 hosts, under the 4096 cap.
        let scope = Scope::parse("10.0.0.0/20", false).expect("under cap");
        assert_eq!(scope.hosts.len(), 4094);
    }
}
