use rustmap_types::{
    DetectionMethod, HostStatus, PortState, Protocol, ScanType, TimingTemplate,
};

pub fn scan_type_from_str(s: &str) -> Result<ScanType, String> {
    match s.to_lowercase().as_str() {
        "connect" | "tcp_connect" | "t" => Ok(ScanType::TcpConnect),
        "syn" | "tcp_syn" | "s" => Ok(ScanType::TcpSyn),
        "fin" | "tcp_fin" | "f" => Ok(ScanType::TcpFin),
        "null" | "tcp_null" | "n" => Ok(ScanType::TcpNull),
        "xmas" | "tcp_xmas" | "x" => Ok(ScanType::TcpXmas),
        "ack" | "tcp_ack" | "a" => Ok(ScanType::TcpAck),
        "window" | "tcp_window" | "w" => Ok(ScanType::TcpWindow),
        "maimon" | "tcp_maimon" | "m" => Ok(ScanType::TcpMaimon),
        "udp" | "u" => Ok(ScanType::Udp),
        "ping" => Ok(ScanType::Ping),
        "sctp_init" | "sctp" | "z" => Ok(ScanType::SctpInit),
        _ => Err(format!("unknown scan type: '{s}'")),
    }
}

pub fn scan_type_to_str(st: ScanType) -> &'static str {
    match st {
        ScanType::TcpConnect => "connect",
        ScanType::TcpSyn => "syn",
        ScanType::TcpFin => "fin",
        ScanType::TcpNull => "null",
        ScanType::TcpXmas => "xmas",
        ScanType::TcpAck => "ack",
        ScanType::TcpWindow => "window",
        ScanType::TcpMaimon => "maimon",
        ScanType::Udp => "udp",
        ScanType::Ping => "ping",
        ScanType::SctpInit => "sctp_init",
    }
}

pub fn port_state_to_str(ps: PortState) -> &'static str {
    match ps {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
        PortState::Unfiltered => "unfiltered",
        PortState::OpenFiltered => "open|filtered",
        PortState::ClosedFiltered => "closed|filtered",
    }
}

pub fn protocol_to_str(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Sctp => "sctp",
    }
}

pub fn host_status_to_str(hs: HostStatus) -> &'static str {
    match hs {
        HostStatus::Up => "up",
        HostStatus::Down => "down",
        HostStatus::Unknown => "unknown",
    }
}

pub fn timing_from_value(v: u8) -> Result<TimingTemplate, String> {
    match v {
        0 => Ok(TimingTemplate::Paranoid),
        1 => Ok(TimingTemplate::Sneaky),
        2 => Ok(TimingTemplate::Polite),
        3 => Ok(TimingTemplate::Normal),
        4 => Ok(TimingTemplate::Aggressive),
        5 => Ok(TimingTemplate::Insane),
        n => Err(format!("invalid timing template: {n} (must be 0-5)")),
    }
}

pub fn detection_method_to_str(dm: DetectionMethod) -> &'static str {
    match dm {
        DetectionMethod::None => "none",
        DetectionMethod::PortBased => "table",
        DetectionMethod::Banner => "banner",
        DetectionMethod::Probe => "probe",
        DetectionMethod::TlsProbe => "tls-probe",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_type_from_str_all_variants() {
        assert_eq!(scan_type_from_str("connect").unwrap(), ScanType::TcpConnect);
        assert_eq!(scan_type_from_str("syn").unwrap(), ScanType::TcpSyn);
        assert_eq!(scan_type_from_str("fin").unwrap(), ScanType::TcpFin);
        assert_eq!(scan_type_from_str("null").unwrap(), ScanType::TcpNull);
        assert_eq!(scan_type_from_str("xmas").unwrap(), ScanType::TcpXmas);
        assert_eq!(scan_type_from_str("ack").unwrap(), ScanType::TcpAck);
        assert_eq!(scan_type_from_str("window").unwrap(), ScanType::TcpWindow);
        assert_eq!(scan_type_from_str("maimon").unwrap(), ScanType::TcpMaimon);
        assert_eq!(scan_type_from_str("udp").unwrap(), ScanType::Udp);
        assert_eq!(scan_type_from_str("ping").unwrap(), ScanType::Ping);
        // Also test single-letter aliases
        assert_eq!(scan_type_from_str("S").unwrap(), ScanType::TcpSyn);
        assert_eq!(scan_type_from_str("T").unwrap(), ScanType::TcpConnect);
        assert_eq!(scan_type_from_str("U").unwrap(), ScanType::Udp);
    }

    #[test]
    fn scan_type_from_str_invalid() {
        assert!(scan_type_from_str("invalid").is_err());
        assert!(scan_type_from_str("").is_err());
    }

    #[test]
    fn timing_from_value_valid() {
        assert_eq!(timing_from_value(0).unwrap(), TimingTemplate::Paranoid);
        assert_eq!(timing_from_value(3).unwrap(), TimingTemplate::Normal);
        assert_eq!(timing_from_value(5).unwrap(), TimingTemplate::Insane);
    }

    #[test]
    fn timing_from_value_invalid() {
        assert!(timing_from_value(6).is_err());
        assert!(timing_from_value(255).is_err());
    }

    #[test]
    fn scan_type_to_str_all_variants() {
        assert_eq!(scan_type_to_str(ScanType::TcpConnect), "connect");
        assert_eq!(scan_type_to_str(ScanType::TcpSyn), "syn");
        assert_eq!(scan_type_to_str(ScanType::Udp), "udp");
        assert_eq!(scan_type_to_str(ScanType::Ping), "ping");
    }

    #[test]
    fn port_state_to_str_all_variants() {
        assert_eq!(port_state_to_str(PortState::Open), "open");
        assert_eq!(port_state_to_str(PortState::Closed), "closed");
        assert_eq!(port_state_to_str(PortState::Filtered), "filtered");
        assert_eq!(port_state_to_str(PortState::Unfiltered), "unfiltered");
        assert_eq!(port_state_to_str(PortState::OpenFiltered), "open|filtered");
        assert_eq!(port_state_to_str(PortState::ClosedFiltered), "closed|filtered");
    }

    #[test]
    fn detection_method_to_str_all() {
        assert_eq!(detection_method_to_str(DetectionMethod::None), "none");
        assert_eq!(detection_method_to_str(DetectionMethod::PortBased), "table");
        assert_eq!(detection_method_to_str(DetectionMethod::Banner), "banner");
        assert_eq!(detection_method_to_str(DetectionMethod::Probe), "probe");
        assert_eq!(detection_method_to_str(DetectionMethod::TlsProbe), "tls-probe");
    }
}
