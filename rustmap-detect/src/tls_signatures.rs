use std::collections::HashSet;

use rustmap_types::TlsServerFingerprint;

/// A TLS library signature used to infer the OS from ServerHello characteristics.
#[derive(Debug, Clone)]
pub struct TlsSignature {
    /// TLS library name (e.g., "Schannel", "OpenSSL", "SecureTransport").
    pub tls_library: &'static str,
    /// Inferred OS family.
    pub os_family: &'static str,
    /// Inferred OS generation.
    pub os_generation: &'static str,
    /// Cipher suites this library typically selects.
    pub preferred_ciphers: &'static [u16],
    /// Extensions typically present in ServerHello.
    pub expected_extensions: &'static [u16],
    /// Whether this library commonly supports TLS 1.3.
    pub supports_tls13: bool,
}

/// Result of matching a TLS fingerprint against the signature database.
#[derive(Debug, Clone)]
pub struct TlsMatch {
    pub os_family: String,
    pub os_generation: String,
    pub tls_library: String,
    pub score: u16,
}

/// Database of TLS library signatures for OS inference.
pub struct TlsSignatureDb {
    pub signatures: Vec<TlsSignature>,
}

impl Default for TlsSignatureDb {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsSignatureDb {
    pub fn new() -> Self {
        Self {
            signatures: built_in_signatures(),
        }
    }

    /// Match a TLS fingerprint against known signatures.
    /// Returns the best match, or None if no signature scores above zero.
    pub fn match_fingerprint(&self, fp: &TlsServerFingerprint) -> Option<TlsMatch> {
        let mut best: Option<TlsMatch> = None;

        for sig in &self.signatures {
            let score = score_tls_match(fp, sig);
            if score > 0 && best.as_ref().is_none_or(|b| score > b.score) {
                best = Some(TlsMatch {
                    os_family: sig.os_family.to_string(),
                    os_generation: sig.os_generation.to_string(),
                    tls_library: sig.tls_library.to_string(),
                    score,
                });
            }
        }

        best
    }
}

/// Score a TLS fingerprint against a signature (0-100).
///
/// Scoring breakdown:
/// - Cipher suite match: 40 points
/// - Extension set similarity (Jaccard): 35 points
/// - TLS version compatibility: 25 points
fn score_tls_match(fp: &TlsServerFingerprint, sig: &TlsSignature) -> u16 {
    let mut score: u16 = 0;
    let max_score: u16 = 100;

    // Cipher suite preference (40 points)
    if sig.preferred_ciphers.contains(&fp.cipher_suite) {
        score += 40;
    }

    // Extension set match (35 points) — Jaccard similarity
    if !sig.expected_extensions.is_empty() {
        let fp_ext_set: HashSet<u16> = fp.extensions.iter().copied().collect();
        let sig_ext_set: HashSet<u16> = sig.expected_extensions.iter().copied().collect();

        let intersection = fp_ext_set.intersection(&sig_ext_set).count();
        let union = fp_ext_set.union(&sig_ext_set).count();
        if union > 0 {
            score += (35 * intersection as u16) / union as u16;
        }
    }

    // TLS version compatibility (25 points)
    let is_tls13 = fp.tls_version >= 0x0304;
    if is_tls13 == sig.supports_tls13 {
        score += 25;
    } else if sig.supports_tls13 && !is_tls13 {
        // Server may support 1.3 but negotiated 1.2 — partial credit
        score += 10;
    }

    // Normalize to 0-100
    (score * 100) / max_score
}

/// Well-known ServerHello extension types used in signatures.
mod ext_ids {
    pub const RENEGOTIATION_INFO: u16 = 0xFF01;
    pub const EC_POINT_FORMATS: u16 = 0x000B;
    pub const SESSION_TICKET: u16 = 0x0023;
    pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
    pub const ENCRYPT_THEN_MAC: u16 = 0x0016;
}

fn built_in_signatures() -> Vec<TlsSignature> {
    use ext_ids::*;

    vec![
        // Schannel — Windows 10/11
        TlsSignature {
            tls_library: "Schannel",
            os_family: "Windows",
            os_generation: "10/11",
            preferred_ciphers: &[
                0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
                0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384 (TLS 1.3)
                0x1301, // TLS_AES_128_GCM_SHA256 (TLS 1.3)
            ],
            expected_extensions: &[RENEGOTIATION_INFO, EXTENDED_MASTER_SECRET],
            supports_tls13: true,
        },
        // Schannel — Windows Server 2016-2022
        TlsSignature {
            tls_library: "Schannel",
            os_family: "Windows",
            os_generation: "Server 2016-2022",
            preferred_ciphers: &[0xC030, 0xC02F, 0x009D, 0x009C],
            expected_extensions: &[RENEGOTIATION_INFO, EXTENDED_MASTER_SECRET],
            supports_tls13: true,
        },
        // OpenSSL modern (1.1.1+) — Linux
        TlsSignature {
            tls_library: "OpenSSL",
            os_family: "Linux",
            os_generation: "4.x-6.x",
            preferred_ciphers: &[
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xC02F, 0xC030, 0xC02B, 0xC02C,
            ],
            expected_extensions: &[
                RENEGOTIATION_INFO,
                EC_POINT_FORMATS,
                SESSION_TICKET,
                EXTENDED_MASTER_SECRET,
                ENCRYPT_THEN_MAC,
            ],
            supports_tls13: true,
        },
        // OpenSSL older (1.0.x) — Linux
        TlsSignature {
            tls_library: "OpenSSL",
            os_family: "Linux",
            os_generation: "2.6.x-3.x",
            preferred_ciphers: &[0xC02F, 0xC030, 0x009C, 0x009D, 0x002F, 0x0035],
            expected_extensions: &[RENEGOTIATION_INFO, EC_POINT_FORMATS, SESSION_TICKET],
            supports_tls13: false,
        },
        // SecureTransport — macOS
        TlsSignature {
            tls_library: "SecureTransport",
            os_family: "macOS",
            os_generation: "12-15",
            preferred_ciphers: &[0x1301, 0x1302, 0x1303, 0xC02F, 0xC030, 0xC02B, 0xC02C],
            expected_extensions: &[RENEGOTIATION_INFO, EXTENDED_MASTER_SECRET],
            supports_tls13: true,
        },
        // LibreSSL — OpenBSD
        TlsSignature {
            tls_library: "LibreSSL",
            os_family: "OpenBSD",
            os_generation: "7.x",
            preferred_ciphers: &[
                0x1303, // CHACHA20 often preferred on OpenBSD
                0x1301, 0x1302, 0xC02F, 0xC030,
            ],
            expected_extensions: &[RENEGOTIATION_INFO, EC_POINT_FORMATS, EXTENDED_MASTER_SECRET],
            supports_tls13: true,
        },
        // OpenSSL — FreeBSD
        TlsSignature {
            tls_library: "OpenSSL",
            os_family: "FreeBSD",
            os_generation: "13-14",
            preferred_ciphers: &[0x1301, 0x1302, 0x1303, 0xC02F, 0xC030, 0xC02B, 0xC02C],
            expected_extensions: &[
                RENEGOTIATION_INFO,
                EC_POINT_FORMATS,
                SESSION_TICKET,
                EXTENDED_MASTER_SECRET,
                ENCRYPT_THEN_MAC,
            ],
            supports_tls13: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_has_signatures() {
        let db = TlsSignatureDb::new();
        assert!(db.signatures.len() >= 5);
    }

    #[test]
    fn match_schannel_fingerprint() {
        let db = TlsSignatureDb::new();
        let fp = TlsServerFingerprint {
            tls_version: 0x0303,
            cipher_suite: 0xC030, // ECDHE_RSA_AES_256_GCM — Schannel preference
            extensions: vec![0xFF01, 0x0017], // renegotiation_info + EMS
            compression_method: 0,
            alpn: None,
            ja4s: None,
            sni: None,
            certificate_chain: None,
        };

        let m = db.match_fingerprint(&fp).unwrap();
        assert_eq!(m.os_family, "Windows");
    }

    #[test]
    fn match_openssl_fingerprint() {
        let db = TlsSignatureDb::new();
        let fp = TlsServerFingerprint {
            tls_version: 0x0304,  // TLS 1.3
            cipher_suite: 0x1301, // AES_128_GCM_SHA256
            extensions: vec![0xFF01, 0x000B, 0x0023, 0x0017, 0x0016],
            compression_method: 0,
            alpn: None,
            ja4s: None,
            sni: None,
            certificate_chain: None,
        };

        let m = db.match_fingerprint(&fp).unwrap();
        assert_eq!(m.os_family, "Linux");
    }

    #[test]
    fn match_old_openssl_no_tls13() {
        let db = TlsSignatureDb::new();
        let fp = TlsServerFingerprint {
            tls_version: 0x0303, // TLS 1.2 only
            cipher_suite: 0xC02F,
            extensions: vec![0xFF01, 0x000B, 0x0023], // No EMS or ETM
            compression_method: 0,
            alpn: None,
            ja4s: None,
            sni: None,
            certificate_chain: None,
        };

        let m = db.match_fingerprint(&fp).unwrap();
        // Should match old Linux OpenSSL
        assert_eq!(m.os_family, "Linux");
        assert_eq!(m.os_generation, "2.6.x-3.x");
    }

    #[test]
    fn scoring_cipher_and_extensions_combined() {
        let sig = &built_in_signatures()[0]; // Schannel Windows 10/11
        let fp = TlsServerFingerprint {
            tls_version: 0x0304,
            cipher_suite: 0xC030,             // Matches Schannel
            extensions: vec![0xFF01, 0x0017], // Exact match
            compression_method: 0,
            alpn: None,
            ja4s: None,
            sni: None,
            certificate_chain: None,
        };

        let score = score_tls_match(&fp, sig);
        assert!(
            score >= 80,
            "cipher + extension + version match should score >=80, got {score}"
        );
    }

    #[test]
    fn scoring_no_cipher_match_reduces_score() {
        let sig = &built_in_signatures()[0]; // Schannel
        let fp = TlsServerFingerprint {
            tls_version: 0x0304,
            cipher_suite: 0x0000, // Unknown cipher
            extensions: vec![0xFF01, 0x0017],
            compression_method: 0,
            alpn: None,
            ja4s: None,
            sni: None,
            certificate_chain: None,
        };

        let score = score_tls_match(&fp, sig);
        assert!(
            score < 70,
            "no cipher match should reduce score, got {score}"
        );
    }

    #[test]
    fn scoring_empty_fingerprint_low() {
        let sig = &built_in_signatures()[0]; // Schannel
        let fp = TlsServerFingerprint {
            tls_version: 0x0303,
            cipher_suite: 0x0000,
            extensions: vec![],
            compression_method: 0,
            alpn: None,
            ja4s: None,
            sni: None,
            certificate_chain: None,
        };

        let score = score_tls_match(&fp, sig);
        assert!(
            score < 30,
            "empty fingerprint should score low, got {score}"
        );
    }

    #[test]
    fn tls_version_mismatch_partial_credit() {
        let sig = &built_in_signatures()[2]; // OpenSSL modern (supports TLS 1.3)
        let fp = TlsServerFingerprint {
            tls_version: 0x0303, // TLS 1.2 — server didn't negotiate 1.3
            cipher_suite: 0xC02F,
            extensions: vec![0xFF01, 0x000B, 0x0023, 0x0017, 0x0016],
            compression_method: 0,
            alpn: None,
            ja4s: None,
            sni: None,
            certificate_chain: None,
        };

        let score = score_tls_match(&fp, sig);
        // Should get partial credit for version (10 instead of 25)
        assert!(score > 50, "partial version credit expected, got {score}");
    }
}
