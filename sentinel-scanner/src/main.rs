//! sentinel-scanner CLI.
//!
//! Exit codes: 0 = success, 1 = error, 2 = invalid scope.

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use sentinel_scanner::network::portscan::parse_ports;
use sentinel_scanner::output::api;
use sentinel_scanner::output::json::write_scan_json;
use sentinel_scanner::{Criticality, ScanConfig, ScanError, Tier, TrustZone};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

/// Exit code for invalid scope (SPEC CLI contract).
const EXIT_INVALID_SCOPE: u8 = 2;
/// Exit code for generic errors.
const EXIT_ERROR: u8 = 1;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TierArg {
    Daily,
    Authority,
    Hacker,
    Military,
}

impl From<TierArg> for Tier {
    fn from(arg: TierArg) -> Self {
        match arg {
            TierArg::Daily => Tier::Daily,
            TierArg::Authority => Tier::Authority,
            TierArg::Hacker => Tier::Hacker,
            TierArg::Military => Tier::Military,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ZoneArg {
    Internet,
    Dmz,
    Internal,
    Mgmt,
    Airgap,
}

impl From<ZoneArg> for TrustZone {
    fn from(arg: ZoneArg) -> Self {
        match arg {
            ZoneArg::Internet => TrustZone::Internet,
            ZoneArg::Dmz => TrustZone::Dmz,
            ZoneArg::Internal => TrustZone::Internal,
            ZoneArg::Mgmt => TrustZone::Mgmt,
            ZoneArg::Airgap => TrustZone::Airgap,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CriticalityArg {
    Dc,
    App,
    Workstation,
    Iot,
}

impl From<CriticalityArg> for Criticality {
    fn from(arg: CriticalityArg) -> Self {
        match arg {
            CriticalityArg::Dc => Criticality::Dc,
            CriticalityArg::App => Criticality::App,
            CriticalityArg::Workstation => Criticality::Workstation,
            CriticalityArg::Iot => Criticality::Iot,
        }
    }
}

/// SENTINEL core scanner engine (unprivileged TCP-connect scanner).
#[derive(Debug, Parser)]
#[command(name = "sentinel-scanner", version, about)]
struct Cli {
    /// Target: CIDR, single IPv4, or comma-separated list.
    #[arg(long)]
    target: String,

    /// Security tier.
    #[arg(long, value_enum, default_value_t = TierArg::Daily)]
    tier: TierArg,

    /// Output path for scan.json.
    #[arg(long, default_value = "scan.json")]
    output: PathBuf,

    /// Analyzer base URL; when set, scan.json is POSTed to {url}/analyze.
    #[arg(long)]
    analyzer_url: Option<String>,

    /// Allow scanning public (non-RFC1918/loopback) address space.
    #[arg(long)]
    allow_public: bool,

    /// Maximum in-flight connection attempts.
    #[arg(long, default_value_t = sentinel_scanner::DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// Ports: 'top-1000' (builtin), 'all', or comma list/ranges (22,80,8000-8100).
    #[arg(long, default_value = "top-1000")]
    ports: String,

    /// Per-connection timeout in milliseconds.
    #[arg(long, default_value_t = sentinel_scanner::DEFAULT_TIMEOUT_MS)]
    timeout_ms: u64,

    /// Override trust zone for every host (default: loopback=mgmt,
    /// private=internal, public=internet).
    #[arg(long, value_enum)]
    trust_zone: Option<ZoneArg>,

    /// Override criticality for every host (default: workstation).
    #[arg(long, value_enum)]
    criticality: Option<CriticalityArg>,

    /// Skip host discovery and port-scan every host in scope (nmap -Pn).
    /// Automatically enabled for scopes of 8 hosts or fewer.
    #[arg(long, visible_alias = "pn")]
    skip_discovery: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(RunFailure::Scope(e)) => {
            eprintln!("invalid scope: {e}");
            ExitCode::from(EXIT_INVALID_SCOPE)
        }
        Err(RunFailure::Other(e)) => {
            eprintln!("error: {e:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

/// Top-level failure split so scope errors map to exit code 2.
enum RunFailure {
    Scope(sentinel_scanner::config::scope::ScopeError),
    Other(anyhow::Error),
}

async fn run(cli: Cli) -> Result<(), RunFailure> {
    let ports = parse_ports(&cli.ports)
        .map_err(|e| anyhow::anyhow!(e))
        .context("invalid --ports")
        .map_err(RunFailure::Other)?;

    let mut config = ScanConfig::new(cli.target.clone(), Tier::from(cli.tier));
    config.allow_public = cli.allow_public;
    config.concurrency = cli.concurrency;
    config.ports = ports;
    config.timeout = Duration::from_millis(cli.timeout_ms);
    config.trust_zone = cli.trust_zone.map(TrustZone::from);
    config.criticality = cli.criticality.map(Criticality::from);
    config.skip_discovery = cli.skip_discovery;

    // Scope summary before touching the network.
    let scope = sentinel_scanner::config::scope::Scope::parse(&cli.target, cli.allow_public)
        .map_err(RunFailure::Scope)?;
    let summary = scope.summary();
    eprintln!(
        "scope: {} host(s) in '{}' ({}..{}, {})",
        summary.host_count,
        summary.target,
        summary
            .first
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".to_string()),
        summary
            .last
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".to_string()),
        if summary.all_private {
            "private/loopback"
        } else {
            "contains public space"
        }
    );

    let report = sentinel_scanner::run_scan(&config)
        .await
        .map_err(|e| match e {
            ScanError::Scope(scope_err) => RunFailure::Scope(scope_err),
            other => RunFailure::Other(anyhow::anyhow!(other)),
        })?;

    write_scan_json(&report, &cli.output)
        .map_err(|e| anyhow::anyhow!(e))
        .map_err(RunFailure::Other)?;
    eprintln!(
        "scan complete: {} host(s) live, {} finding(s), risk_score={:.2} -> {}",
        report.hosts.len(),
        report.vulnerabilities.len(),
        report.risk_score,
        cli.output.display()
    );

    if let Some(url) = cli.analyzer_url.as_deref() {
        let client = api::build_client()
            .map_err(|e| anyhow::anyhow!(e))
            .map_err(RunFailure::Other)?;
        let body = api::post_scan(&client, url, &report)
            .await
            .map_err(|e| anyhow::anyhow!(e))
            .context("analyzer /analyze call failed")
            .map_err(RunFailure::Other)?;
        eprintln!("analyzer accepted scan ({} bytes returned)", body.len());
    }

    Ok(())
}
