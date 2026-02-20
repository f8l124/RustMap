use rustmap_types::TcpOptionKind;

/// A single OS fingerprint signature for active detection.
/// Matched against TCP fingerprint data extracted from probe responses.
#[derive(Debug, Clone)]
pub struct OsSignature {
    /// OS family name (e.g., "Linux", "Windows", "macOS").
    pub os_family: &'static str,
    /// OS generation/version (e.g., "4.x-5.x", "10/11").
    pub os_generation: &'static str,
    /// Expected initial TTL (64, 128, or 255).
    pub initial_ttl: u8,
    /// Expected TCP window sizes (match any).
    pub window_sizes: &'static [u16],
    /// Expected TCP option types in order (values ignored).
    pub tcp_options_order: &'static [TcpOptionKind],
    /// Expected Don't Fragment bit setting.
    pub df_bit: bool,
}

/// Database of built-in OS signatures for active fingerprinting.
/// Values derived from public TCP/IP stack documentation and p0f reference data.
pub struct OsSignatureDb {
    pub signatures: Vec<OsSignature>,
}

impl Default for OsSignatureDb {
    fn default() -> Self {
        Self::new()
    }
}

impl OsSignatureDb {
    /// Create a new signature database with all built-in entries.
    pub fn new() -> Self {
        Self {
            signatures: built_in_signatures(),
        }
    }
}

/// Linux option order: MSS, SACK_PERM, Timestamp, NOP, WindowScale
const LINUX_OPTIONS: &[TcpOptionKind] = &[
    TcpOptionKind::Mss,
    TcpOptionKind::SackPermitted,
    TcpOptionKind::Timestamp,
    TcpOptionKind::Nop,
    TcpOptionKind::WindowScale,
];

/// Windows option order: MSS, NOP, WindowScale, NOP, NOP, SACK_PERM
const WINDOWS_OPTIONS: &[TcpOptionKind] = &[
    TcpOptionKind::Mss,
    TcpOptionKind::Nop,
    TcpOptionKind::WindowScale,
    TcpOptionKind::Nop,
    TcpOptionKind::Nop,
    TcpOptionKind::SackPermitted,
];

/// macOS/iOS option order: MSS, NOP, WindowScale, NOP, NOP, Timestamp, SACK_PERM, EOL
const MACOS_OPTIONS: &[TcpOptionKind] = &[
    TcpOptionKind::Mss,
    TcpOptionKind::Nop,
    TcpOptionKind::WindowScale,
    TcpOptionKind::Nop,
    TcpOptionKind::Nop,
    TcpOptionKind::Timestamp,
    TcpOptionKind::SackPermitted,
    TcpOptionKind::Eol,
];

/// FreeBSD option order: MSS, NOP, WindowScale, NOP, NOP, Timestamp, SACK_PERM
const FREEBSD_OPTIONS: &[TcpOptionKind] = &[
    TcpOptionKind::Mss,
    TcpOptionKind::Nop,
    TcpOptionKind::WindowScale,
    TcpOptionKind::Nop,
    TcpOptionKind::Nop,
    TcpOptionKind::Timestamp,
    TcpOptionKind::SackPermitted,
];

/// OpenBSD option order: MSS, NOP, NOP, SACK_PERM, NOP, WindowScale
const OPENBSD_OPTIONS: &[TcpOptionKind] = &[
    TcpOptionKind::Mss,
    TcpOptionKind::Nop,
    TcpOptionKind::Nop,
    TcpOptionKind::SackPermitted,
    TcpOptionKind::Nop,
    TcpOptionKind::WindowScale,
];

/// Solaris option order: MSS, NOP, WindowScale, NOP, NOP, SACK_PERM
const SOLARIS_OPTIONS: &[TcpOptionKind] = &[
    TcpOptionKind::Mss,
    TcpOptionKind::Nop,
    TcpOptionKind::WindowScale,
    TcpOptionKind::Nop,
    TcpOptionKind::Nop,
    TcpOptionKind::SackPermitted,
];

/// Cisco IOS — minimal options, often just MSS
const CISCO_OPTIONS: &[TcpOptionKind] = &[TcpOptionKind::Mss];

/// Build the complete set of built-in OS fingerprint signatures (~25 entries).
fn built_in_signatures() -> Vec<OsSignature> {
    vec![
        // --- Linux ---
        OsSignature {
            os_family: "Linux",
            os_generation: "2.6.x",
            initial_ttl: 64,
            window_sizes: &[5840, 5720, 14600],
            tcp_options_order: LINUX_OPTIONS,
            df_bit: true,
        },
        OsSignature {
            os_family: "Linux",
            os_generation: "3.x",
            initial_ttl: 64,
            window_sizes: &[14600, 29200, 5840],
            tcp_options_order: LINUX_OPTIONS,
            df_bit: true,
        },
        OsSignature {
            os_family: "Linux",
            os_generation: "4.x",
            initial_ttl: 64,
            window_sizes: &[29200, 26883, 28960],
            tcp_options_order: LINUX_OPTIONS,
            df_bit: true,
        },
        OsSignature {
            os_family: "Linux",
            os_generation: "5.x",
            initial_ttl: 64,
            window_sizes: &[65535, 64240, 29200],
            tcp_options_order: LINUX_OPTIONS,
            df_bit: true,
        },
        OsSignature {
            os_family: "Linux",
            os_generation: "6.x",
            initial_ttl: 64,
            window_sizes: &[65535, 64240],
            tcp_options_order: LINUX_OPTIONS,
            df_bit: true,
        },
        // --- Windows ---
        OsSignature {
            os_family: "Windows",
            os_generation: "7",
            initial_ttl: 128,
            window_sizes: &[8192],
            tcp_options_order: WINDOWS_OPTIONS,
            df_bit: true,
        },
        OsSignature {
            os_family: "Windows",
            os_generation: "8/8.1",
            initial_ttl: 128,
            window_sizes: &[8192, 65535],
            tcp_options_order: WINDOWS_OPTIONS,
            df_bit: true,
        },
        OsSignature {
            os_family: "Windows",
            os_generation: "10",
            initial_ttl: 128,
            window_sizes: &[65535, 64240, 8192],
            tcp_options_order: WINDOWS_OPTIONS,
            df_bit: true,
        },
        OsSignature {
            os_family: "Windows",
            os_generation: "11",
            initial_ttl: 128,
            window_sizes: &[65535, 64240],
            tcp_options_order: WINDOWS_OPTIONS,
            df_bit: true,
        },
        OsSignature {
            os_family: "Windows",
            os_generation: "Server 2016",
            initial_ttl: 128,
            window_sizes: &[65535, 8192],
            tcp_options_order: WINDOWS_OPTIONS,
            df_bit: true,
        },
        OsSignature {
            os_family: "Windows",
            os_generation: "Server 2019/2022",
            initial_ttl: 128,
            window_sizes: &[65535, 64240],
            tcp_options_order: WINDOWS_OPTIONS,
            df_bit: true,
        },
        // --- macOS ---
        OsSignature {
            os_family: "macOS",
            os_generation: "12-13",
            initial_ttl: 64,
            window_sizes: &[65535],
            tcp_options_order: MACOS_OPTIONS,
            df_bit: true,
        },
        OsSignature {
            os_family: "macOS",
            os_generation: "14-15",
            initial_ttl: 64,
            window_sizes: &[65535],
            tcp_options_order: MACOS_OPTIONS,
            df_bit: true,
        },
        // --- iOS ---
        OsSignature {
            os_family: "iOS",
            os_generation: "16-17",
            initial_ttl: 64,
            window_sizes: &[65535],
            tcp_options_order: MACOS_OPTIONS,
            df_bit: true,
        },
        // --- FreeBSD ---
        OsSignature {
            os_family: "FreeBSD",
            os_generation: "13",
            initial_ttl: 64,
            window_sizes: &[65535],
            tcp_options_order: FREEBSD_OPTIONS,
            df_bit: true,
        },
        OsSignature {
            os_family: "FreeBSD",
            os_generation: "14",
            initial_ttl: 64,
            window_sizes: &[65535],
            tcp_options_order: FREEBSD_OPTIONS,
            df_bit: true,
        },
        // --- OpenBSD ---
        OsSignature {
            os_family: "OpenBSD",
            os_generation: "7.x",
            initial_ttl: 64,
            window_sizes: &[16384],
            tcp_options_order: OPENBSD_OPTIONS,
            df_bit: true,
        },
        // --- Android ---
        OsSignature {
            os_family: "Android",
            os_generation: "12+",
            initial_ttl: 64,
            window_sizes: &[65535, 64240],
            tcp_options_order: LINUX_OPTIONS,
            df_bit: true,
        },
        // --- Solaris ---
        OsSignature {
            os_family: "Solaris",
            os_generation: "11",
            initial_ttl: 255,
            window_sizes: &[49640, 32768],
            tcp_options_order: SOLARIS_OPTIONS,
            df_bit: true,
        },
        // --- Cisco IOS ---
        OsSignature {
            os_family: "Cisco IOS",
            os_generation: "15.x",
            initial_ttl: 255,
            window_sizes: &[4128, 4096],
            tcp_options_order: CISCO_OPTIONS,
            df_bit: false,
        },
        OsSignature {
            os_family: "Cisco IOS",
            os_generation: "XE 17.x",
            initial_ttl: 255,
            window_sizes: &[4128, 8192],
            tcp_options_order: CISCO_OPTIONS,
            df_bit: false,
        },
        // --- Juniper JunOS ---
        OsSignature {
            os_family: "JunOS",
            os_generation: "21+",
            initial_ttl: 64,
            window_sizes: &[65535, 16384],
            tcp_options_order: FREEBSD_OPTIONS, // JunOS is FreeBSD-based
            df_bit: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_db_has_entries() {
        let db = OsSignatureDb::new();
        assert!(db.signatures.len() >= 20, "expected at least 20 signatures");
    }

    #[test]
    fn linux_signatures_have_correct_ttl() {
        let db = OsSignatureDb::new();
        for sig in &db.signatures {
            if sig.os_family == "Linux" {
                assert_eq!(sig.initial_ttl, 64);
            }
        }
    }

    #[test]
    fn windows_signatures_have_correct_ttl() {
        let db = OsSignatureDb::new();
        for sig in &db.signatures {
            if sig.os_family == "Windows" {
                assert_eq!(sig.initial_ttl, 128);
            }
        }
    }

    #[test]
    fn macos_and_freebsd_differ_by_eol() {
        let db = OsSignatureDb::new();
        let macos = db
            .signatures
            .iter()
            .find(|s| s.os_family == "macOS")
            .unwrap();
        let freebsd = db
            .signatures
            .iter()
            .find(|s| s.os_family == "FreeBSD")
            .unwrap();

        // macOS has EOL at end, FreeBSD does not
        assert_eq!(
            macos.tcp_options_order.last(),
            Some(&TcpOptionKind::Eol),
            "macOS should end with EOL"
        );
        assert_ne!(
            freebsd.tcp_options_order.last(),
            Some(&TcpOptionKind::Eol),
            "FreeBSD should NOT end with EOL"
        );
    }

    #[test]
    fn linux_and_windows_options_differ() {
        assert_ne!(LINUX_OPTIONS, WINDOWS_OPTIONS);
        // Linux starts with MSS, SACK_PERM
        assert_eq!(LINUX_OPTIONS[0], TcpOptionKind::Mss);
        assert_eq!(LINUX_OPTIONS[1], TcpOptionKind::SackPermitted);
        // Windows starts with MSS, NOP
        assert_eq!(WINDOWS_OPTIONS[0], TcpOptionKind::Mss);
        assert_eq!(WINDOWS_OPTIONS[1], TcpOptionKind::Nop);
    }

    #[test]
    fn cisco_has_minimal_options() {
        let db = OsSignatureDb::new();
        let cisco = db
            .signatures
            .iter()
            .find(|s| s.os_family == "Cisco IOS")
            .unwrap();
        assert_eq!(cisco.tcp_options_order.len(), 1);
        assert_eq!(cisco.tcp_options_order[0], TcpOptionKind::Mss);
        assert!(!cisco.df_bit);
    }
}
