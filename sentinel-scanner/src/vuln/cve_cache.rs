//! Embedded CVE cache (SQLite via rusqlite, bundled).
//!
//! The database is built in-memory at runtime from a deterministic, curated
//! seed set of high-signal service → CVE mappings. Ranges follow the
//! convention `version_start` inclusive, `version_end` exclusive; a `None`
//! bound is unbounded, and an entry with neither bound applies to any
//! detected version of the service (used for exposure-class findings where
//! the mere presence of the service is the risk).

use rusqlite::Connection;
use thiserror::Error;

/// Errors from the CVE cache.
#[derive(Debug, Error)]
pub enum CveCacheError {
    /// SQLite failure while building or querying the cache.
    #[error("cve cache error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Seed dataset version. Bumped whenever seed rows or flags change; tests pin
/// it so dataset drift is a deliberate, reviewable act (METHODOLOGY.md R3/R5).
pub const SEED_VERSION: &str = "2026.08.1";

/// CISA Known Exploited Vulnerabilities catalog feed (JSON). The seed's `kev`
/// flags are verified against this catalog; refresh = re-verify, bump
/// SEED_VERSION, review the diff.
pub const KEV_FEED_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// One curated service→CVE mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct CveEntry {
    /// CVE identifier.
    pub cve_id: String,
    /// Canonical service name (fingerprint output), e.g. `openssh`.
    pub service: String,
    /// Inclusive lower version bound (None = unbounded).
    pub version_start: Option<String>,
    /// Exclusive upper version bound (None = unbounded).
    pub version_end: Option<String>,
    /// CVSS base score (0.0-10.0).
    pub cvss: f64,
    /// EPSS probability (0.0-1.0).
    pub epss: f64,
    /// Short human-readable summary.
    pub summary: String,
    /// CISA KEV catalog membership (verified against catalog 2026.07.29).
    /// KEV findings floor the deterministic risk score at 9.0 (scorer.rs).
    pub kev: bool,
}

impl CveEntry {
    /// True when the entry carries any version constraint.
    pub fn has_version_range(&self) -> bool {
        self.version_start.is_some() || self.version_end.is_some()
    }
}

/// Raw seed row: (cve_id, service, version_start, version_end, cvss, epss,
/// summary, kev) with the start-inclusive / end-exclusive range convention.
type SeedRow = (
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
    f64,
    f64,
    &'static str,
    bool,
);

/// Deterministic curated seed set (>= 25 mappings). Insertion order is fixed
/// so cache contents are byte-for-byte reproducible across runs.
pub fn seed_entries() -> Vec<CveEntry> {
    let raw: &[SeedRow] = &[
        // --- OpenSSH ------------------------------------------------------
        ("CVE-2024-6387", "openssh", Some("8.5"), Some("9.8"), 8.1, 0.53,
         "OpenSSH regreSSHion: unauthenticated remote code execution via sshd signal handler race", false),
        ("CVE-2023-38408", "openssh", None, Some("9.3.2"), 9.8, 0.21,
         "OpenSSH ssh-agent PKCS#11 provider forwarding remote code execution", false),
        ("CVE-2021-28041", "openssh", None, Some("8.5"), 7.1, 0.12,
         "OpenSSH ssh-agent double free reachable via forwarded agent socket", false),
        ("CVE-2018-15473", "openssh", None, Some("7.8"), 5.3, 0.87,
         "OpenSSH username enumeration via malformed authentication packets", false),
        // --- Redis --------------------------------------------------------
        ("CVE-2022-0543", "redis", None, None, 10.0, 0.44,
         "Redis Lua sandbox escape (Debian/Ubuntu packaging); exposed unauthenticated Redis is trivially exploitable", true),
        ("CVE-2025-32023", "redis", Some("6.2"), Some("7.4.5"), 7.0, 0.02,
         "Redis hyperloglog out-of-bounds write via authenticated commands", false),
        // --- Apache httpd -------------------------------------------------
        ("CVE-2021-41773", "apache", Some("2.4.49"), Some("2.4.50"), 7.5, 0.97,
         "Apache httpd 2.4.49 path traversal and remote code execution", true),
        ("CVE-2021-42013", "apache", Some("2.4.50"), Some("2.4.51"), 9.8, 0.97,
         "Apache httpd 2.4.50 incomplete fix for CVE-2021-41773 enables RCE", true),
        ("CVE-2019-0211", "apache", Some("2.4.17"), Some("2.4.39"), 7.8, 0.90,
         "Apache httpd prefork MPM local privilege escalation to root", true),
        // --- nginx --------------------------------------------------------
        ("CVE-2021-23017", "nginx", Some("0.6.18"), Some("1.20.1"), 7.7, 0.40,
         "nginx resolver off-by-one heap write via crafted DNS response", false),
        ("CVE-2017-7529", "nginx", Some("0.5.6"), Some("1.13.3"), 7.5, 0.94,
         "nginx range header integer overflow discloses cached responses", false),
        // --- MySQL --------------------------------------------------------
        ("CVE-2012-2122", "mysql", None, Some("5.5.25"), 7.5, 0.93,
         "MySQL/MariaDB authentication bypass via memcmp return value (repeatable)", false),
        ("CVE-2016-6662", "mysql", None, Some("5.5.52"), 9.8, 0.72,
         "MySQL remote root code execution via malicious configuration injection", false),
        // --- PostgreSQL ---------------------------------------------------
        ("CVE-2024-7348", "postgresql", None, Some("16.4"), 7.5, 0.05,
         "PostgreSQL pg_dump relation replacement TOCTOU executes arbitrary SQL", false),
        ("CVE-2019-9193", "postgresql", Some("9.3"), Some("11.3"), 7.2, 0.09,
         "PostgreSQL COPY TO/FROM PROGRAM executes OS commands as superuser", false),
        // --- SMB / Windows ------------------------------------------------
        ("CVE-2017-0144", "smb", None, None, 9.3, 0.97,
         "Windows SMBv1 remote code execution (EternalBlue, MS17-010)", true),
        ("CVE-2020-0796", "smb", None, None, 10.0, 0.51,
         "Windows SMBv3.1.1 compression remote code execution (SMBGhost)", true),
        ("CVE-2017-7494", "smb", Some("3.5.0"), Some("4.6.4"), 9.8, 0.97,
         "Samba is_known_pipename arbitrary module load RCE (SambaCry)", true),
        // --- RDP ----------------------------------------------------------
        ("CVE-2019-0708", "rdp", None, None, 9.8, 0.97,
         "Windows Remote Desktop Services pre-authentication RCE (BlueKeep)", true),
        // --- Elasticsearch ------------------------------------------------
        ("CVE-2015-1427", "elasticsearch", None, Some("1.4.3"), 9.3, 0.97,
         "Elasticsearch Groovy scripting sandbox bypass remote code execution", true),
        ("CVE-2014-3120", "elasticsearch", None, Some("1.2.0"), 7.5, 0.97,
         "Elasticsearch dynamic scripting MVEL remote code execution (default config)", true),
        // --- MongoDB ------------------------------------------------------
        ("CVE-2019-2389", "mongodb", Some("3.6.0"), Some("3.6.13"), 6.5, 0.03,
         "MongoDB incorrect access control on views of system collections", false),
        // --- Docker -------------------------------------------------------
        ("CVE-2019-5736", "docker", None, Some("18.9.2"), 8.6, 0.43,
         "runc container breakout via /proc/self/exe overwrite (Docker < 18.09.2)", false),
        // --- Java / Log4j class -------------------------------------------
        ("CVE-2021-44228", "java", Some("2.0"), Some("2.15.0"), 10.0, 0.97,
         "Apache Log4j2 JNDI lookup remote code execution (Log4Shell)", true),
        // --- vsftpd -------------------------------------------------------
        ("CVE-2011-2523", "vsftpd", Some("2.3.4"), Some("2.3.5"), 10.0, 0.97,
         "vsftpd 2.3.4 backdoor remote command execution via smiley-face login", false),
        // --- Exim ---------------------------------------------------------
        ("CVE-2019-10149", "exim", Some("4.87"), Some("4.92"), 9.8, 0.97,
         "Exim remote command execution as root (Return of the WIZard)", true),
        ("CVE-2019-15846", "exim", None, Some("4.92.2"), 9.8, 0.26,
         "Exim TLS SNI heap buffer overflow remote code execution", false),
        // --- ProFTPD ------------------------------------------------------
        ("CVE-2015-3306", "proftpd", None, Some("1.3.6"), 10.0, 0.97,
         "ProFTPD mod_copy unauthenticated remote file copy / code execution", false),
        // --- Tomcat AJP ---------------------------------------------------
        ("CVE-2020-1938", "ajp13", None, Some("9.0.31"), 9.8, 0.97,
         "Apache Tomcat AJP connector file read/inclusion (Ghostcat)", true),
        // --- Microsoft IIS ------------------------------------------------
        ("CVE-2017-7269", "iis", Some("6.0"), Some("6.1"), 9.8, 0.97,
         "IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow remote code execution", true),
    ];

    raw.iter()
        .map(
            |&(cve_id, service, start, end, cvss, epss, summary, kev)| CveEntry {
                cve_id: cve_id.to_string(),
                service: service.to_string(),
                version_start: start.map(str::to_string),
                version_end: end.map(str::to_string),
                cvss,
                epss,
                summary: summary.to_string(),
                kev,
            },
        )
        .collect()
}

/// In-memory SQLite CVE cache seeded from [`seed_entries`].
pub struct CveCache {
    conn: Connection,
}

impl CveCache {
    /// Builds a fresh in-memory cache with the deterministic seed set.
    pub fn in_memory() -> Result<Self, CveCacheError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE cves (
                id INTEGER PRIMARY KEY,
                cve_id TEXT NOT NULL,
                service TEXT NOT NULL,
                version_start TEXT,
                version_end TEXT,
                cvss REAL NOT NULL,
                epss REAL NOT NULL,
                summary TEXT NOT NULL,
                kev INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_cves_service ON cves(service);",
        )?;
        let cache = Self { conn };
        cache.seed()?;
        Ok(cache)
    }

    /// Inserts the curated seed set in a fixed order.
    fn seed(&self) -> Result<(), CveCacheError> {
        let mut stmt = self.conn.prepare(
            "INSERT INTO cves (cve_id, service, version_start, version_end, cvss, epss, summary, kev)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for entry in seed_entries() {
            stmt.execute(rusqlite::params![
                entry.cve_id,
                entry.service,
                entry.version_start,
                entry.version_end,
                entry.cvss,
                entry.epss,
                entry.summary,
                entry.kev,
            ])?;
        }
        Ok(())
    }

    /// All candidate entries for a canonical service name, in seed order.
    pub fn find_by_service(&self, service: &str) -> Result<Vec<CveEntry>, CveCacheError> {
        let mut stmt = self.conn.prepare(
            "SELECT cve_id, service, version_start, version_end, cvss, epss, summary, kev
             FROM cves WHERE service = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map([service], |row| {
            Ok(CveEntry {
                cve_id: row.get(0)?,
                service: row.get(1)?,
                version_start: row.get(2)?,
                version_end: row.get(3)?,
                cvss: row.get(4)?,
                epss: row.get(5)?,
                summary: row.get(6)?,
                kev: row.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Total number of seeded entries (sanity check for tests).
    pub fn len(&self) -> Result<usize, CveCacheError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM cves", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// True when the cache holds no entries (always false after seeding).
    pub fn is_empty(&self) -> Result<bool, CveCacheError> {
        Ok(self.len()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_has_at_least_25_entries() {
        let entries = seed_entries();
        assert!(entries.len() >= 25, "seed set: {}", entries.len());
    }

    #[test]
    fn seed_ids_are_unique_and_services_nonempty() {
        let entries = seed_entries();
        let mut ids: Vec<&str> = entries.iter().map(|e| e.cve_id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), entries.len(), "duplicate CVE ids in seed");
        assert!(entries.iter().all(|e| !e.service.is_empty()));
        assert!(entries
            .iter()
            .all(|e| (0.0..=10.0).contains(&e.cvss) && (0.0..=1.0).contains(&e.epss)));
    }

    #[test]
    fn cache_roundtrips_seed_deterministically() {
        let cache = CveCache::in_memory().expect("cache");
        assert_eq!(cache.len().expect("len"), seed_entries().len());
        let openssh = cache.find_by_service("openssh").expect("query");
        assert_eq!(openssh.len(), 4);
        assert_eq!(openssh[0].cve_id, "CVE-2024-6387");
        assert_eq!(openssh[0].version_start.as_deref(), Some("8.5"));
        assert_eq!(openssh[0].version_end.as_deref(), Some("9.8"));
        // kev flag survives the SQLite roundtrip.
        assert!(!openssh[0].kev);
        let smb = cache.find_by_service("smb").expect("query");
        assert!(smb.iter().all(|e| e.kev));
    }

    /// KEV flags verified against the CISA catalog (v2026.07.29): exactly
    /// these 14 seed CVEs are known-exploited.
    #[test]
    fn kev_flags_match_cisa_catalog_verification() {
        const EXPECTED_KEV: [&str; 14] = [
            "CVE-2014-3120", "CVE-2015-1427", "CVE-2017-0144", "CVE-2017-7269",
            "CVE-2017-7494", "CVE-2019-0211", "CVE-2019-0708", "CVE-2019-10149",
            "CVE-2020-0796", "CVE-2020-1938", "CVE-2021-41773", "CVE-2021-42013",
            "CVE-2021-44228", "CVE-2022-0543",
        ];
        let entries = seed_entries();
        let mut flagged: Vec<&str> = entries
            .iter()
            .filter(|e| e.kev)
            .map(|e| e.cve_id.as_str())
            .collect();
        flagged.sort_unstable();
        let mut expected = EXPECTED_KEV.to_vec();
        expected.sort_unstable();
        assert_eq!(flagged, expected);
    }

    #[test]
    fn seed_version_is_pinned() {
        // Bumping SEED_VERSION without reviewing the seed diff breaks this
        // test on purpose (METHODOLOGY.md R3/R5: dataset drift is deliberate).
        assert_eq!(SEED_VERSION, "2026.08.1");
        assert!(KEV_FEED_URL.starts_with("https://www.cisa.gov/"));
    }

    #[test]
    fn unknown_service_yields_no_candidates() {
        let cache = CveCache::in_memory().expect("cache");
        assert!(cache.find_by_service("gopher").expect("query").is_empty());
    }
}
