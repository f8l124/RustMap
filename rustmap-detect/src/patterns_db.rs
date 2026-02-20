use rustmap_types::{DetectionMethod, ServiceInfo};

use crate::pattern::MatchPattern;

/// Database of match patterns for banner/response analysis.
pub struct PatternDatabase {
    patterns: Vec<MatchPattern>,
}

impl PatternDatabase {
    /// Build the default pattern database.
    #[allow(clippy::vec_init_then_push)]
    pub fn new() -> Self {
        let mut patterns = Vec::new();

        // --- SSH ---
        // OpenSSH with version extraction
        patterns.push(
            MatchPattern::new(
                r"SSH-([\d.]+)-OpenSSH[_-]([\w.p]+)",
                "ssh",
                None,    // product via literal
                Some(2), // version = OpenSSH version
                Some(1), // info = protocol version
                Some("OpenSSH"),
            )
            .unwrap(),
        );
        // Dropbear SSH
        patterns.push(
            MatchPattern::new(
                r"SSH-([\d.]+)-dropbear[_-]?([\w.]*)",
                "ssh",
                None,
                Some(2),
                Some(1),
                Some("Dropbear sshd"),
            )
            .unwrap(),
        );
        // Generic SSH
        patterns.push(
            MatchPattern::new(
                r"SSH-([\d.]+)-(.+?)[\r\n]",
                "ssh",
                Some(2),
                Some(1),
                None,
                None,
            )
            .unwrap(),
        );

        // --- FTP (specific patterns, before generic 220) ---
        // vsftpd
        patterns.push(
            MatchPattern::new(
                r"220 \(vsFTPd ([\d.]+)\)",
                "ftp",
                None,
                Some(1),
                None,
                Some("vsftpd"),
            )
            .unwrap(),
        );
        // ProFTPD / PureFTPd / other named FTP
        patterns.push(
            MatchPattern::new(
                r"220[- ].*?(\w+FTP\w*)[/ ]([\d.]+)",
                "ftp",
                Some(1),
                Some(2),
                None,
                None,
            )
            .unwrap(),
        );

        // --- SMTP (before generic 220 fallback) ---
        // Postfix
        patterns.push(
            MatchPattern::new(
                r"220[- ].*?Postfix",
                "smtp",
                None,
                None,
                None,
                Some("Postfix smtpd"),
            )
            .unwrap(),
        );
        // ESMTP with server name
        patterns.push(
            MatchPattern::new(
                r"220[- ].*?ESMTP\s+(.+?)[\r\n]",
                "smtp",
                Some(1),
                None,
                None,
                None,
            )
            .unwrap(),
        );
        // SMTP with explicit mention
        patterns.push(
            MatchPattern::new(r"220[- ].*?SMTP.*?[\r\n]", "smtp", None, None, None, None).unwrap(),
        );

        // --- Generic 220 fallback (after specific FTP/SMTP patterns) ---
        // If we get here, it's likely FTP (most SMTP servers mention SMTP/ESMTP)
        patterns.push(
            MatchPattern::new(r"220[- ](.+?)[\r\n]", "ftp", None, None, Some(1), None).unwrap(),
        );

        // --- POP3 ---
        patterns.push(
            MatchPattern::new(r"\+OK\s+(.+?)[\r\n]", "pop3", None, None, Some(1), None).unwrap(),
        );

        // --- IMAP ---
        patterns.push(
            MatchPattern::new(r"\* OK\s+(.+?)[\r\n]", "imap", None, None, Some(1), None).unwrap(),
        );

        // --- MySQL ---
        // MySQL binary greeting: starts with packet length + sequence + protocol version + version string
        patterns.push(
            MatchPattern::new(
                r"(?s)^.{4}\x0a([\d.]+)",
                "mysql",
                None,
                Some(1),
                None,
                Some("MySQL"),
            )
            .unwrap(),
        );

        // --- MariaDB ---
        patterns.push(
            MatchPattern::new(
                r"(?s)^.{4}\x0a([\d.]+-MariaDB)",
                "mysql",
                None,
                Some(1),
                None,
                Some("MariaDB"),
            )
            .unwrap(),
        );

        // --- Redis ---
        patterns.push(
            MatchPattern::new(
                r"-ERR.*?redis",
                "redis",
                None,
                None,
                None,
                Some("Redis key-value store"),
            )
            .unwrap(),
        );

        // --- PostgreSQL ---
        // PostgreSQL authentication response: 'R' (0x52) + 4-byte big-endian length
        // (always \x00\x00\x00\x08 for auth-ok/cleartext/md5) + 4-byte auth type code.
        // Also match ErrorResponse 'E' with severity field containing "FATAL" which
        // PostgreSQL sends to unauthorized or malformed startup packets.
        patterns.push(
            MatchPattern::new(
                r"(?s)^(?:R\x00\x00\x00[\x08-\x17]\x00\x00\x00[\x00-\x0c]|E.{4}SFATAL\x00)",
                "postgresql",
                None,
                None,
                None,
                Some("PostgreSQL"),
            )
            .unwrap(),
        );

        // --- HTTP response patterns (for active probe responses) ---
        // Apache with version
        patterns.push(
            MatchPattern::new(
                r"Server: Apache/([\d.]+)",
                "http",
                None,
                Some(1),
                None,
                Some("Apache httpd"),
            )
            .unwrap(),
        );
        // nginx with version
        patterns.push(
            MatchPattern::new(
                r"Server: nginx/([\d.]+)",
                "http",
                None,
                Some(1),
                None,
                Some("nginx"),
            )
            .unwrap(),
        );
        // Microsoft IIS
        patterns.push(
            MatchPattern::new(
                r"Server: Microsoft-IIS/([\d.]+)",
                "http",
                None,
                Some(1),
                None,
                Some("Microsoft IIS httpd"),
            )
            .unwrap(),
        );
        // LiteSpeed
        patterns.push(
            MatchPattern::new(
                r"Server: LiteSpeed",
                "http",
                None,
                None,
                None,
                Some("LiteSpeed httpd"),
            )
            .unwrap(),
        );
        // Caddy
        patterns.push(
            MatchPattern::new(
                r"Server: Caddy",
                "http",
                None,
                None,
                None,
                Some("Caddy httpd"),
            )
            .unwrap(),
        );
        // Generic Server header
        patterns.push(
            MatchPattern::new(r"Server: ([^\r\n]+)", "http", Some(1), None, None, None).unwrap(),
        );
        // HTTP response without Server header
        patterns
            .push(MatchPattern::new(r"^HTTP/[\d.]+ \d+", "http", None, None, None, None).unwrap());

        // --- HTTP/2 ---
        // HTTP/2 SETTINGS frame response (frame type 0x04)
        patterns.push(
            MatchPattern::new(r"(?s)^.{3}\x04", "http", None, None, None, Some("HTTP/2")).unwrap(),
        );

        // --- Telnet ---
        // Telnet negotiation starts with IAC (0xFF)
        patterns.push(
            MatchPattern::new(r"(?s)^\xff[\xfb-\xfe]", "telnet", None, None, None, None).unwrap(),
        );

        Self { patterns }
    }

    /// Try to match banner/response data against all patterns.
    ///
    /// Returns the first match found (patterns are ordered by specificity).
    pub fn match_data(&self, data: &[u8], method: DetectionMethod) -> Option<ServiceInfo> {
        for pattern in &self.patterns {
            if let Some(info) = pattern.try_match(data, method) {
                return Some(info);
            }
        }
        None
    }
}

impl Default for PatternDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_openssh_banner() {
        let db = PatternDatabase::new();
        let banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
        let result = db.match_data(banner, DetectionMethod::Banner).unwrap();

        assert_eq!(result.name, "ssh");
        assert_eq!(result.product.as_deref(), Some("OpenSSH"));
        assert_eq!(result.version.as_deref(), Some("8.9p1"));
    }

    #[test]
    fn match_dropbear_banner() {
        let db = PatternDatabase::new();
        let banner = b"SSH-2.0-dropbear_2022.83\r\n";
        let result = db.match_data(banner, DetectionMethod::Banner).unwrap();

        assert_eq!(result.name, "ssh");
        assert_eq!(result.product.as_deref(), Some("Dropbear sshd"));
        assert_eq!(result.version.as_deref(), Some("2022.83"));
    }

    #[test]
    fn match_vsftpd_banner() {
        let db = PatternDatabase::new();
        let banner = b"220 (vsFTPd 3.0.5)\r\n";
        let result = db.match_data(banner, DetectionMethod::Banner).unwrap();

        assert_eq!(result.name, "ftp");
        assert_eq!(result.product.as_deref(), Some("vsftpd"));
        assert_eq!(result.version.as_deref(), Some("3.0.5"));
    }

    #[test]
    fn match_proftpd_banner() {
        let db = PatternDatabase::new();
        let banner = b"220 ProFTPD 1.3.5 Server ready.\r\n";
        let result = db.match_data(banner, DetectionMethod::Banner).unwrap();

        assert_eq!(result.name, "ftp");
        assert_eq!(result.product.as_deref(), Some("ProFTPD"));
        assert_eq!(result.version.as_deref(), Some("1.3.5"));
    }

    #[test]
    fn match_postfix_smtp() {
        let db = PatternDatabase::new();
        let banner = b"220 mail.example.com ESMTP Postfix\r\n";
        let result = db.match_data(banner, DetectionMethod::Banner).unwrap();

        assert_eq!(result.name, "smtp");
        assert_eq!(result.product.as_deref(), Some("Postfix smtpd"));
    }

    #[test]
    fn match_nginx_server_header() {
        let db = PatternDatabase::new();
        let response =
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n";
        let result = db.match_data(response, DetectionMethod::Probe).unwrap();

        assert_eq!(result.name, "http");
        assert_eq!(result.product.as_deref(), Some("nginx"));
        assert_eq!(result.version.as_deref(), Some("1.24.0"));
    }

    #[test]
    fn match_apache_server_header() {
        let db = PatternDatabase::new();
        let response = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n\r\n";
        let result = db.match_data(response, DetectionMethod::Probe).unwrap();

        assert_eq!(result.name, "http");
        assert_eq!(result.product.as_deref(), Some("Apache httpd"));
        assert_eq!(result.version.as_deref(), Some("2.4.52"));
    }

    #[test]
    fn match_iis_server_header() {
        let db = PatternDatabase::new();
        let response = b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n";
        let result = db.match_data(response, DetectionMethod::Probe).unwrap();

        assert_eq!(result.name, "http");
        assert_eq!(result.product.as_deref(), Some("Microsoft IIS httpd"));
        assert_eq!(result.version.as_deref(), Some("10.0"));
    }

    #[test]
    fn match_pop3_banner() {
        let db = PatternDatabase::new();
        let banner = b"+OK Dovecot (Ubuntu) ready.\r\n";
        let result = db.match_data(banner, DetectionMethod::Banner).unwrap();

        assert_eq!(result.name, "pop3");
        assert_eq!(result.info.as_deref(), Some("Dovecot (Ubuntu) ready."));
    }

    #[test]
    fn match_imap_banner() {
        let db = PatternDatabase::new();
        let banner = b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n";
        let result = db.match_data(banner, DetectionMethod::Banner).unwrap();

        assert_eq!(result.name, "imap");
    }

    #[test]
    fn no_match_for_unknown_data() {
        let db = PatternDatabase::new();
        let data = b"\x00\x01\x02\x03random binary garbage";
        let result = db.match_data(data, DetectionMethod::Banner);

        assert!(result.is_none());
    }
}
