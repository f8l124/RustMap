use std::path::Path;
use std::sync::Arc;

use rustmap_types::{OsFingerprint, OsProbeResults, Port, PortState, TcpFingerprint, TcpOptionKind};

use crate::os_signatures::{OsSignature, OsSignatureDb};
use crate::p0f_parser::P0fDatabase;
use crate::tls_signatures::TlsSignatureDb;

/// Scoring weights for OS fingerprint matching (total: 100).
/// When TLS data is available, weights are redistributed to include TLS signal.
const WEIGHT_TCP_OPTIONS: u16 = 40;
const WEIGHT_TTL: u16 = 25;
const WEIGHT_WINDOW: u16 = 20;
const WEIGHT_DF: u16 = 10;
const WEIGHT_MSS: u16 = 5;

/// TLS signal weight — applied as a bonus on top of the base 100-point score.
/// This avoids breaking existing scoring when TLS is unavailable.
const TLS_BONUS_MAX: u16 = 15;

/// Minimum confidence score (0-100) to report a match.
const MIN_CONFIDENCE: u8 = 50;

/// OS fingerprint detector combining active signatures, optional p0f database,
/// and TLS ServerHello fingerprinting.
pub struct OsDetector {
    signature_db: Arc<OsSignatureDb>,
    p0f_db: Option<Arc<P0fDatabase>>,
    tls_db: Arc<TlsSignatureDb>,
}

/// A single scored match candidate.
#[derive(Debug, Clone)]
struct ScoredMatch {
    os_family: String,
    os_generation: String,
    score: u16,
}

impl Default for OsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OsDetector {
    /// Create a new OsDetector with built-in signatures only.
    pub fn new() -> Self {
        Self {
            signature_db: Arc::new(OsSignatureDb::new()),
            p0f_db: None,
            tls_db: Arc::new(TlsSignatureDb::new()),
        }
    }

    /// Create an OsDetector with built-in signatures and a p0f database file.
    pub fn with_p0f(p0f_path: &Path) -> Self {
        let p0f_db = P0fDatabase::parse_file(p0f_path).ok().map(Arc::new);

        Self {
            signature_db: Arc::new(OsSignatureDb::new()),
            p0f_db,
            tls_db: Arc::new(TlsSignatureDb::new()),
        }
    }

    /// Detect the OS from probe results using score-based matching.
    ///
    /// Priority for fingerprint selection:
    /// 1. `syn_open` (SYN/ACK from open port — richest data)
    /// 2. `passive` (SYN/ACK captured during port scan)
    /// 3. `syn_closed` (RST from closed port — less options usually)
    /// 4. `ack_open` (RST from ACK probe — minimal options)
    pub fn detect(&self, probe_results: &OsProbeResults) -> OsFingerprint {
        // Pick the best available fingerprint
        let primary_fp = probe_results
            .syn_open
            .as_ref()
            .or(probe_results.passive.as_ref())
            .or(probe_results.syn_closed.as_ref())
            .or(probe_results.ack_open.as_ref());

        let Some(fingerprint) = primary_fp else {
            return OsFingerprint {
                os_family: None,
                os_generation: None,
                accuracy: None,
                probe_results: probe_results.clone(),
            };
        };

        // Score against built-in active signatures
        let mut best = self.match_active_signatures(fingerprint);

        // Also try p0f database if available
        if let Some(p0f_db) = &self.p0f_db
            && let Some(p0f_match) = p0f_db.match_synack(fingerprint)
        {
            let p0f_score = p0f_match.score as u16;
            if best.as_ref().is_none_or(|b| p0f_score > b.score) {
                best = Some(ScoredMatch {
                    os_family: p0f_match.label.name,
                    os_generation: p0f_match.label.flavor,
                    score: p0f_score,
                });
            }
        }

        // Apply cross-probe boosting if multiple probes agree on TTL
        if let Some(ref mut m) = best {
            let boost = self.cross_probe_boost(probe_results, fingerprint);
            m.score = (m.score + boost).min(100);
        }

        // Apply TLS bonus if TLS fingerprint is available and agrees with the best match
        if let Some(ref mut m) = best
            && let Some(ref tls_fp) = probe_results.tls
        {
            let tls_bonus = self.tls_bonus(tls_fp, &m.os_family);
            m.score = (m.score + tls_bonus).min(100);
        }

        // If no TCP match but TLS data is available, try TLS-only matching
        if best.is_none()
            && let Some(ref tls_fp) = probe_results.tls
            && let Some(tls_match) = self.tls_db.match_fingerprint(tls_fp)
            && tls_match.score >= MIN_CONFIDENCE as u16
        {
            // Scale TLS-only score down since it's a weaker signal alone
            let scaled_score = (tls_match.score * 70 / 100).max(MIN_CONFIDENCE as u16);
            best = Some(ScoredMatch {
                os_family: tls_match.os_family,
                os_generation: tls_match.os_generation,
                score: scaled_score,
            });
        }

        match best {
            Some(m) if m.score as u8 >= MIN_CONFIDENCE => OsFingerprint {
                os_family: Some(m.os_family),
                os_generation: Some(m.os_generation),
                accuracy: Some(m.score.min(100) as u8),
                probe_results: probe_results.clone(),
            },
            _ => OsFingerprint {
                os_family: None,
                os_generation: None,
                accuracy: None,
                probe_results: probe_results.clone(),
            },
        }
    }

    /// Score a fingerprint against all built-in active signatures.
    fn match_active_signatures(&self, fingerprint: &TcpFingerprint) -> Option<ScoredMatch> {
        let mut best: Option<ScoredMatch> = None;

        for sig in &self.signature_db.signatures {
            let score = score_against_signature(fingerprint, sig);
            if score >= MIN_CONFIDENCE as u16
                && best.as_ref().is_none_or(|b| score > b.score)
            {
                best = Some(ScoredMatch {
                    os_family: sig.os_family.to_string(),
                    os_generation: sig.os_generation.to_string(),
                    score,
                });
            }
        }

        best
    }

    /// Boost confidence if multiple probe types show consistent TTL.
    fn cross_probe_boost(&self, results: &OsProbeResults, _primary: &TcpFingerprint) -> u16 {
        let ttls: Vec<u8> = [
            results.syn_open.as_ref(),
            results.syn_closed.as_ref(),
            results.ack_open.as_ref(),
            results.passive.as_ref(),
        ]
        .iter()
        .filter_map(|fp| fp.map(|f| f.initial_ttl))
        .collect();

        if ttls.len() >= 2 && ttls.windows(2).all(|w| w[0] == w[1]) {
            5 // Small boost for consistent TTL across probes
        } else {
            0
        }
    }

    /// Bonus points from TLS fingerprinting when it agrees with the TCP-based match.
    fn tls_bonus(
        &self,
        tls_fp: &rustmap_types::TlsServerFingerprint,
        tcp_os_family: &str,
    ) -> u16 {
        if let Some(tls_match) = self.tls_db.match_fingerprint(tls_fp) {
            if tls_match.os_family == tcp_os_family {
                // TLS agrees with TCP — full bonus
                TLS_BONUS_MAX
            } else {
                // TLS disagrees — no bonus (don't penalize, server TLS config may be atypical)
                0
            }
        } else {
            0
        }
    }
}

/// Infer OS from service banners when raw probe-based detection fails.
///
/// Returns an `OsFingerprint` with lower confidence (service-based inference is
/// less reliable than active probing, so accuracy is capped at 70%).
pub fn infer_os_from_services(ports: &[Port]) -> Option<OsFingerprint> {
    let mut votes: Vec<(&str, &str)> = Vec::new();

    for port in ports {
        if port.state != PortState::Open {
            continue;
        }
        let Some(ref si) = port.service_info else {
            continue;
        };

        // Check the info field first (most specific: "Ubuntu Linux", "Debian", etc.)
        if let Some(ref info) = si.info {
            let info_lower = info.to_lowercase();
            if info_lower.contains("ubuntu")
                || info_lower.contains("debian")
                || info_lower.contains("red hat")
                || info_lower.contains("centos")
                || info_lower.contains("fedora")
                || info_lower.contains("rhel")
            {
                votes.push(("Linux", ""));
            } else if info_lower.contains("windows") {
                votes.push(("Windows", ""));
            } else if info_lower.contains("freebsd") {
                votes.push(("FreeBSD", ""));
            }
        }

        // Check the product name
        if let Some(ref product) = si.product {
            let product_lower = product.to_lowercase();
            if product_lower.contains("openssh")
                || product_lower.contains("dropbear")
                || product_lower.contains("vsftpd")
                || product_lower.contains("proftpd")
                || product_lower.contains("pure-ftpd")
                || product_lower.contains("postfix")
                || product_lower.contains("dovecot")
                || product_lower.contains("exim")
            {
                votes.push(("Linux", ""));
            } else if product_lower.contains("microsoft")
                || product_lower.contains("iis")
                || product_lower.contains("httpapi")
            {
                votes.push(("Windows", ""));
            }
        }
    }

    if votes.is_empty() {
        return None;
    }

    // Count votes per OS family
    let mut linux_count = 0usize;
    let mut windows_count = 0usize;
    let mut freebsd_count = 0usize;

    for (family, _) in &votes {
        match *family {
            "Linux" => linux_count += 1,
            "Windows" => windows_count += 1,
            "FreeBSD" => freebsd_count += 1,
            _ => {}
        }
    }

    let (os_family, os_generation) =
        if linux_count >= windows_count && linux_count >= freebsd_count && linux_count > 0 {
            ("Linux", "")
        } else if windows_count >= linux_count && windows_count >= freebsd_count && windows_count > 0
        {
            ("Windows", "")
        } else if freebsd_count > 0 {
            ("FreeBSD", "")
        } else {
            return None;
        };

    // Cap accuracy: service inference is weaker than probe-based detection.
    // Scale by number of agreeing services (more = higher confidence, up to 70%).
    let max_votes = linux_count.max(windows_count).max(freebsd_count);
    let accuracy = (40 + max_votes * 10).min(70) as u8;

    Some(OsFingerprint {
        os_family: Some(os_family.to_string()),
        os_generation: if os_generation.is_empty() {
            None
        } else {
            Some(os_generation.to_string())
        },
        accuracy: Some(accuracy),
        probe_results: OsProbeResults::default(),
    })
}

/// Score a fingerprint against a single active signature (0-100).
fn score_against_signature(fp: &TcpFingerprint, sig: &OsSignature) -> u16 {
    let mut score: u16 = 0;

    // TCP Options Order (40 points) — strongest differentiator
    let fp_kinds: Vec<TcpOptionKind> = fp.tcp_options.iter().map(|o| o.kind()).collect();
    if fp_kinds == sig.tcp_options_order {
        score += WEIGHT_TCP_OPTIONS;
    } else {
        let lcs = lcs_length(&fp_kinds, sig.tcp_options_order);
        let max_len = fp_kinds.len().max(sig.tcp_options_order.len());
        if max_len > 0 {
            score += (WEIGHT_TCP_OPTIONS * lcs as u16) / max_len as u16;
        }
    }

    // Initial TTL (25 points)
    if fp.initial_ttl == sig.initial_ttl {
        score += WEIGHT_TTL;
    }

    // Window Size (20 points) — match any of the signature's expected values
    if sig.window_sizes.contains(&fp.window_size) {
        score += WEIGHT_WINDOW;
    } else if !sig.window_sizes.is_empty() {
        // Partial credit if within 10% of any expected value
        let close = sig.window_sizes.iter().any(|&expected| {
            let diff = (fp.window_size as i32 - expected as i32).unsigned_abs();
            let threshold = (expected as u32) / 10;
            diff <= threshold
        });
        if close {
            score += WEIGHT_WINDOW / 2;
        }
    }

    // DF Bit (10 points)
    if fp.df_bit == sig.df_bit {
        score += WEIGHT_DF;
    }

    // MSS (5 points) — weak signal, most hosts use 1460
    if fp.mss.is_some() {
        score += WEIGHT_MSS; // Don't penalize, MSS is network-dependent
    }

    score
}

/// Longest Common Subsequence length for comparing option ordering.
fn lcs_length(a: &[TcpOptionKind], b: &[TcpOptionKind]) -> usize {
    let m = a.len();
    let n = b.len();
    if m == 0 || n == 0 {
        return 0;
    }

    let mut prev = vec![0usize; n + 1];
    let mut curr = vec![0usize; n + 1];

    for i in 1..=m {
        for j in 1..=n {
            if a[i - 1] == b[j - 1] {
                curr[j] = prev[j - 1] + 1;
            } else {
                curr[j] = prev[j].max(curr[j - 1]);
            }
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.fill(0);
    }

    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::TcpOption;

    fn linux_fingerprint() -> TcpFingerprint {
        TcpFingerprint {
            initial_ttl: 64,
            window_size: 29200,
            tcp_options: vec![
                TcpOption::Mss(1460),
                TcpOption::SackPermitted,
                TcpOption::Timestamp(0, 0),
                TcpOption::Nop,
                TcpOption::WindowScale(7),
            ],
            df_bit: true,
            mss: Some(1460),
        }
    }

    fn windows_fingerprint() -> TcpFingerprint {
        TcpFingerprint {
            initial_ttl: 128,
            window_size: 65535,
            tcp_options: vec![
                TcpOption::Mss(1460),
                TcpOption::Nop,
                TcpOption::WindowScale(8),
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::SackPermitted,
            ],
            df_bit: true,
            mss: Some(1460),
        }
    }

    fn macos_fingerprint() -> TcpFingerprint {
        TcpFingerprint {
            initial_ttl: 64,
            window_size: 65535,
            tcp_options: vec![
                TcpOption::Mss(1460),
                TcpOption::Nop,
                TcpOption::WindowScale(6),
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Timestamp(0, 0),
                TcpOption::SackPermitted,
                TcpOption::Eol,
            ],
            df_bit: true,
            mss: Some(1460),
        }
    }

    fn freebsd_fingerprint() -> TcpFingerprint {
        TcpFingerprint {
            initial_ttl: 64,
            window_size: 65535,
            tcp_options: vec![
                TcpOption::Mss(1460),
                TcpOption::Nop,
                TcpOption::WindowScale(6),
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::Timestamp(0, 0),
                TcpOption::SackPermitted,
            ],
            df_bit: true,
            mss: Some(1460),
        }
    }

    #[test]
    fn detect_linux() {
        let detector = OsDetector::new();
        let results = OsProbeResults {
            syn_open: Some(linux_fingerprint()),
            ..Default::default()
        };

        let os = detector.detect(&results);
        assert_eq!(os.os_family.as_deref(), Some("Linux"));
        assert!(os.accuracy.unwrap() >= MIN_CONFIDENCE);
    }

    #[test]
    fn detect_windows() {
        let detector = OsDetector::new();
        let results = OsProbeResults {
            syn_open: Some(windows_fingerprint()),
            ..Default::default()
        };

        let os = detector.detect(&results);
        assert_eq!(os.os_family.as_deref(), Some("Windows"));
        assert!(os.accuracy.unwrap() >= MIN_CONFIDENCE);
    }

    #[test]
    fn detect_macos() {
        let detector = OsDetector::new();
        let results = OsProbeResults {
            syn_open: Some(macos_fingerprint()),
            ..Default::default()
        };

        let os = detector.detect(&results);
        assert_eq!(os.os_family.as_deref(), Some("macOS"));
    }

    #[test]
    fn detect_freebsd() {
        let detector = OsDetector::new();
        let results = OsProbeResults {
            syn_open: Some(freebsd_fingerprint()),
            ..Default::default()
        };

        let os = detector.detect(&results);
        assert_eq!(os.os_family.as_deref(), Some("FreeBSD"));
    }

    #[test]
    fn freebsd_vs_macos_discrimination() {
        let detector = OsDetector::new();

        let macos_results = OsProbeResults {
            syn_open: Some(macos_fingerprint()),
            ..Default::default()
        };
        let freebsd_results = OsProbeResults {
            syn_open: Some(freebsd_fingerprint()),
            ..Default::default()
        };

        let macos_os = detector.detect(&macos_results);
        let freebsd_os = detector.detect(&freebsd_results);

        assert_ne!(
            macos_os.os_family, freebsd_os.os_family,
            "macOS and FreeBSD should be distinguished by trailing EOL"
        );
    }

    #[test]
    fn empty_probes_no_match() {
        let detector = OsDetector::new();
        let results = OsProbeResults::default();

        let os = detector.detect(&results);
        assert!(os.os_family.is_none());
        assert!(os.accuracy.is_none());
    }

    #[test]
    fn passive_fallback() {
        let detector = OsDetector::new();
        let results = OsProbeResults {
            syn_open: None,
            passive: Some(linux_fingerprint()),
            ..Default::default()
        };

        let os = detector.detect(&results);
        assert_eq!(os.os_family.as_deref(), Some("Linux"));
    }

    #[test]
    fn syn_open_preferred_over_passive() {
        let detector = OsDetector::new();
        let results = OsProbeResults {
            syn_open: Some(windows_fingerprint()),
            passive: Some(linux_fingerprint()),
            ..Default::default()
        };

        // syn_open should take priority
        let os = detector.detect(&results);
        assert_eq!(os.os_family.as_deref(), Some("Windows"));
    }

    #[test]
    fn cross_probe_boost_increases_confidence() {
        let detector = OsDetector::new();

        // Single probe
        let single = OsProbeResults {
            syn_open: Some(linux_fingerprint()),
            ..Default::default()
        };
        let os_single = detector.detect(&single);

        // Multiple probes with same TTL
        let multi = OsProbeResults {
            syn_open: Some(linux_fingerprint()),
            syn_closed: Some(TcpFingerprint {
                initial_ttl: 64,
                window_size: 0,
                tcp_options: vec![],
                df_bit: true,
                mss: None,
            }),
            ..Default::default()
        };
        let os_multi = detector.detect(&multi);

        assert!(
            os_multi.accuracy.unwrap() >= os_single.accuracy.unwrap(),
            "multiple consistent probes should give equal or higher confidence"
        );
    }

    #[test]
    fn scoring_perfect_match() {
        let fp = linux_fingerprint();
        let sig = &OsSignatureDb::new()
            .signatures
            .into_iter()
            .find(|s| s.os_family == "Linux" && s.os_generation == "4.x")
            .unwrap();

        let score = score_against_signature(&fp, sig);
        // TTL(25) + Options(40) + Window(20) + DF(10) + MSS(5) = 100
        assert!(score >= 90, "perfect match should score >=90, got {score}");
    }

    #[test]
    fn scoring_ttl_mismatch_drops_significantly() {
        let mut fp = linux_fingerprint();
        fp.initial_ttl = 128; // Wrong TTL for Linux

        let sig = &OsSignatureDb::new()
            .signatures
            .into_iter()
            .find(|s| s.os_family == "Linux")
            .unwrap();

        let score = score_against_signature(&fp, sig);
        assert!(
            score < 80,
            "TTL mismatch should significantly reduce score, got {score}"
        );
    }

    #[test]
    fn scoring_options_mismatch() {
        let fp = TcpFingerprint {
            initial_ttl: 64,
            window_size: 65535,
            tcp_options: vec![TcpOption::Mss(1460)], // Only MSS, missing others
            df_bit: true,
            mss: Some(1460),
        };

        let sig = &OsSignatureDb::new()
            .signatures
            .into_iter()
            .find(|s| s.os_family == "Linux")
            .unwrap();

        let score = score_against_signature(&fp, sig);
        assert!(
            score < 80,
            "options mismatch should reduce score, got {score}"
        );
    }

    #[test]
    fn probe_results_preserved_in_output() {
        let detector = OsDetector::new();
        let results = OsProbeResults {
            syn_open: Some(linux_fingerprint()),
            ..Default::default()
        };

        let os = detector.detect(&results);
        assert!(os.probe_results.syn_open.is_some());
    }

    #[test]
    fn tls_bonus_increases_confidence() {
        let detector = OsDetector::new();

        // Without TLS
        let no_tls = OsProbeResults {
            syn_open: Some(linux_fingerprint()),
            ..Default::default()
        };
        let os_no_tls = detector.detect(&no_tls);

        // With TLS that agrees (OpenSSL → Linux)
        let with_tls = OsProbeResults {
            syn_open: Some(linux_fingerprint()),
            tls: Some(rustmap_types::TlsServerFingerprint {
                tls_version: 0x0304,
                cipher_suite: 0x1301,
                extensions: vec![0xFF01, 0x000B, 0x0023, 0x0017, 0x0016],
                compression_method: 0,
                alpn: None,
                ja4s: None,
                sni: None,
                certificate_chain: None,
            }),
            ..Default::default()
        };
        let os_with_tls = detector.detect(&with_tls);

        assert!(
            os_with_tls.accuracy.unwrap() >= os_no_tls.accuracy.unwrap(),
            "TLS agreement should give equal or higher confidence"
        );
    }

    #[test]
    fn tls_disagreement_no_penalty() {
        let detector = OsDetector::new();

        // TCP says Linux, TLS says Windows (e.g., reverse proxy)
        let results = OsProbeResults {
            syn_open: Some(linux_fingerprint()),
            tls: Some(rustmap_types::TlsServerFingerprint {
                tls_version: 0x0303,
                cipher_suite: 0xC030, // Schannel preference
                extensions: vec![0xFF01, 0x0017], // Windows-like extensions
                compression_method: 0,
                alpn: None,
                ja4s: None,
                sni: None,
                certificate_chain: None,
            }),
            ..Default::default()
        };

        let os = detector.detect(&results);
        // Should still detect Linux (TCP is primary signal)
        assert_eq!(os.os_family.as_deref(), Some("Linux"));
    }

    #[test]
    fn tls_only_detection_when_no_tcp_fingerprint() {
        let detector = OsDetector::new();

        // Only TLS data, no TCP probes
        let results = OsProbeResults {
            tls: Some(rustmap_types::TlsServerFingerprint {
                tls_version: 0x0304,
                cipher_suite: 0x1301,
                extensions: vec![0xFF01, 0x000B, 0x0023, 0x0017, 0x0016],
                compression_method: 0,
                alpn: None,
                ja4s: None,
                sni: None,
                certificate_chain: None,
            }),
            ..Default::default()
        };

        let os = detector.detect(&results);
        // TLS-only detection should work but with lower confidence
        if let Some(family) = &os.os_family {
            assert_eq!(family, "Linux");
            // Scaled down confidence for TLS-only
            assert!(os.accuracy.unwrap() <= 80);
        }
    }

    // --- Service-based OS inference tests ---

    fn make_port_with_service(number: u16, product: Option<&str>, info: Option<&str>) -> Port {
        Port {
            number,
            protocol: rustmap_types::Protocol::Tcp,
            state: PortState::Open,
            service: None,
            service_info: Some(rustmap_types::ServiceInfo {
                name: "test".into(),
                product: product.map(String::from),
                version: None,
                info: info.map(String::from),
                method: rustmap_types::DetectionMethod::Banner,
            }),
            reason: None,
            script_results: vec![],
            tls_info: None,
        }
    }

    #[test]
    fn infer_linux_from_openssh() {
        let ports = vec![make_port_with_service(22, Some("OpenSSH"), None)];
        let result = infer_os_from_services(&ports).unwrap();
        assert_eq!(result.os_family.as_deref(), Some("Linux"));
        assert!(result.accuracy.unwrap() <= 70);
    }

    #[test]
    fn infer_windows_from_iis() {
        let ports = vec![make_port_with_service(
            80,
            Some("Microsoft IIS httpd"),
            None,
        )];
        let result = infer_os_from_services(&ports).unwrap();
        assert_eq!(result.os_family.as_deref(), Some("Windows"));
    }

    #[test]
    fn infer_linux_from_info_field() {
        let ports = vec![make_port_with_service(
            22,
            Some("OpenSSH"),
            Some("Ubuntu Linux; protocol 2.0"),
        )];
        let result = infer_os_from_services(&ports).unwrap();
        assert_eq!(result.os_family.as_deref(), Some("Linux"));
        // Two votes (product + info), so higher confidence
        assert!(result.accuracy.unwrap() >= 50);
    }

    #[test]
    fn infer_none_from_no_services() {
        let ports = vec![Port {
            number: 80,
            protocol: rustmap_types::Protocol::Tcp,
            state: PortState::Open,
            service: None,
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];
        assert!(infer_os_from_services(&ports).is_none());
    }

    #[test]
    fn infer_none_from_closed_ports() {
        let ports = vec![Port {
            number: 22,
            protocol: rustmap_types::Protocol::Tcp,
            state: PortState::Closed,
            service: None,
            service_info: Some(rustmap_types::ServiceInfo {
                name: "ssh".into(),
                product: Some("OpenSSH".into()),
                version: None,
                info: None,
                method: rustmap_types::DetectionMethod::Banner,
            }),
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];
        assert!(infer_os_from_services(&ports).is_none());
    }

    #[test]
    fn infer_higher_confidence_with_multiple_services() {
        let ports = vec![
            make_port_with_service(22, Some("OpenSSH"), None),
            make_port_with_service(80, Some("Apache httpd"), None),
            make_port_with_service(25, Some("Postfix"), None),
        ];
        let result = infer_os_from_services(&ports).unwrap();
        assert_eq!(result.os_family.as_deref(), Some("Linux"));
        assert!(result.accuracy.unwrap() >= 60);
    }
}
