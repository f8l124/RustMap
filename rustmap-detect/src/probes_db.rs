use crate::probe::ServiceProbe;

/// Database of active service probes.
pub struct ProbeDatabase {
    probes: Vec<ServiceProbe>,
}

impl ProbeDatabase {
    /// Build the default probe database.
    pub fn new() -> Self {
        let probes = vec![
            // HTTP GET (rarity 1 — very common, always try for HTTP ports)
            ServiceProbe {
                name: "GetRequest",
                payload: b"GET / HTTP/1.0\r\n\r\n",
                ports: &[80, 443, 8080, 8443, 8000, 8008, 8081, 8888, 9090],
                rarity: 1,
            },
            // Generic CRLF lines (rarity 2 — many text protocols respond)
            ServiceProbe {
                name: "GenericLines",
                payload: b"\r\n\r\n",
                ports: &[],
                rarity: 2,
            },
            // SMTP HELP (rarity 3)
            ServiceProbe {
                name: "Help",
                payload: b"HELP\r\n",
                ports: &[25, 587, 465],
                rarity: 3,
            },
            // HTTP OPTIONS (rarity 4)
            ServiceProbe {
                name: "HTTPOptions",
                payload: b"OPTIONS / HTTP/1.0\r\n\r\n",
                ports: &[80, 443, 8080],
                rarity: 4,
            },
            // RTSP OPTIONS (rarity 5)
            ServiceProbe {
                name: "RTSPRequest",
                payload: b"OPTIONS / RTSP/1.0\r\n\r\n",
                ports: &[554, 8554],
                rarity: 5,
            },
            // HTTP/2 Prior Knowledge (rarity 5)
            // Sends connection preface + empty SETTINGS frame
            ServiceProbe {
                name: "HTTP2PriorKnowledge",
                payload: b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00",
                ports: &[80, 8080, 8443, 50051],
                rarity: 5,
            },
        ];

        Self { probes }
    }

    /// Get probes that should run for a given port and intensity level.
    ///
    /// Returns probes where `rarity <= intensity` AND the port is in the
    /// probe's target port list (or the probe targets all ports).
    pub fn get_probes(&self, port: u16, intensity: u8) -> Vec<&ServiceProbe> {
        self.probes
            .iter()
            .filter(|p| p.rarity <= intensity)
            .filter(|p| p.ports.is_empty() || p.ports.contains(&port))
            .collect()
    }
}

impl Default for ProbeDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_http_probes_at_intensity_1() {
        let db = ProbeDatabase::new();
        let probes = db.get_probes(80, 1);

        assert!(!probes.is_empty());
        assert!(probes.iter().any(|p| p.name == "GetRequest"));
        // GenericLines is rarity 2, should not appear at intensity 1
        // unless port matches (empty ports = all, but rarity > intensity)
        assert!(!probes.iter().any(|p| p.name == "GenericLines"));
    }

    #[test]
    fn get_http_probes_at_intensity_7() {
        let db = ProbeDatabase::new();
        let probes = db.get_probes(80, 7);

        assert!(probes.iter().any(|p| p.name == "GetRequest"));
        assert!(probes.iter().any(|p| p.name == "GenericLines"));
        assert!(probes.iter().any(|p| p.name == "HTTPOptions"));
    }

    #[test]
    fn smtp_probes_for_smtp_port() {
        let db = ProbeDatabase::new();
        let probes = db.get_probes(25, 7);

        assert!(probes.iter().any(|p| p.name == "Help"));
        assert!(probes.iter().any(|p| p.name == "GenericLines"));
        // GetRequest should NOT appear for port 25
        assert!(!probes.iter().any(|p| p.name == "GetRequest"));
    }

    #[test]
    fn intensity_0_returns_nothing() {
        let db = ProbeDatabase::new();
        let probes = db.get_probes(80, 0);

        // Rarity starts at 1, so intensity 0 returns nothing
        assert!(probes.is_empty());
    }

    #[test]
    fn unknown_port_gets_generic_probes() {
        let db = ProbeDatabase::new();
        let probes = db.get_probes(9999, 7);

        // Should get GenericLines (empty ports = all)
        assert!(probes.iter().any(|p| p.name == "GenericLines"));
        // Should NOT get GetRequest (port 9999 not in its list)
        assert!(!probes.iter().any(|p| p.name == "GetRequest"));
    }

    #[test]
    fn http2_probe_for_grpc_port() {
        let db = ProbeDatabase::new();
        let probes = db.get_probes(50051, 5);

        assert!(probes.iter().any(|p| p.name == "HTTP2PriorKnowledge"));
    }

    #[test]
    fn http2_probe_payload_format() {
        let db = ProbeDatabase::new();
        let probes = db.get_probes(80, 5);
        let h2_probe = probes
            .iter()
            .find(|p| p.name == "HTTP2PriorKnowledge")
            .unwrap();
        // Should start with PRI preface
        assert!(
            h2_probe
                .payload
                .starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        );
    }
}
