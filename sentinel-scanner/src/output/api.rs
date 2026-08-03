//! Analyzer API client: POSTs scan.json to the analyzer `/analyze` endpoint.
//! Uses rustls (no native TLS dependency) with a 120s request timeout.

use crate::output::json::ScanReport;
use thiserror::Error;

/// Default request timeout for analyzer calls (SPEC: 120s).
pub const ANALYZER_TIMEOUT_SECS: u64 = 120;

/// Errors talking to the analyzer.
#[derive(Debug, Error)]
pub enum ApiError {
    /// HTTP client construction or transport failure.
    #[error("analyzer request failed: {0}")]
    Transport(#[from] reqwest::Error),
    /// Analyzer answered with a non-success status.
    #[error("analyzer returned status {status}: {body}")]
    Status {
        /// HTTP status code.
        status: reqwest::StatusCode,
        /// Truncated response body for diagnostics.
        body: String,
    },
}

/// Builds the shared HTTP client (rustls, 120s timeout).
pub fn build_client() -> Result<reqwest::Client, ApiError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(ANALYZER_TIMEOUT_SECS))
        .build()?;
    Ok(client)
}

/// POSTs `report` as JSON to `{analyzer_url}/analyze`.
///
/// Returns the response body (the analyzer's `AnalysisOutput` JSON) on any
/// 2xx status; non-2xx statuses become [`ApiError::Status`].
pub async fn post_scan(
    client: &reqwest::Client,
    analyzer_url: &str,
    report: &ScanReport,
) -> Result<String, ApiError> {
    let url = format!("{}/analyze", analyzer_url.trim_end_matches('/'));
    let response = client.post(&url).json(report).send().await?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        let body: String = body.chars().take(512).collect();
        return Err(ApiError::Status { status, body });
    }
    Ok(response.text().await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_builds() {
        assert!(build_client().is_ok());
    }
}
