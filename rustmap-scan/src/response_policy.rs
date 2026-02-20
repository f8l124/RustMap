use rustmap_types::PortState;

/// Policy for interpreting probe responses for a given scan type.
///
/// Different scan types interpret the same network responses differently.
/// For example, a RST response means "closed" for SYN scan, but "unfiltered"
/// for ACK scan. This struct captures those interpretation rules.
#[derive(Debug, Clone)]
pub struct ResponsePolicy {
    /// What PortState when we receive SYN/ACK. None = ignore.
    pub on_syn_ack: Option<PortState>,
    /// What PortState when we receive RST. None = special handling (Window scan).
    pub on_rst: Option<PortState>,
    /// What PortState when we receive ICMP unreachable.
    pub on_icmp_unreachable: PortState,
    /// What PortState when no response after all retries.
    pub on_no_response: PortState,
    /// For Window scan: examine the RST response's TCP window size.
    /// If true, RST with window > 0 → Open, window = 0 → Closed.
    pub check_rst_window: bool,
}

impl ResponsePolicy {
    /// SYN scan: SYN/ACK → Open, RST → Closed, ICMP → Filtered, timeout → Filtered.
    pub fn syn_scan() -> Self {
        Self {
            on_syn_ack: Some(PortState::Open),
            on_rst: Some(PortState::Closed),
            on_icmp_unreachable: PortState::Filtered,
            on_no_response: PortState::Filtered,
            check_rst_window: false,
        }
    }

    /// FIN scan: RST → Closed, ICMP → Filtered, timeout → Open|Filtered.
    pub fn fin_scan() -> Self {
        Self {
            on_syn_ack: None,
            on_rst: Some(PortState::Closed),
            on_icmp_unreachable: PortState::Filtered,
            on_no_response: PortState::OpenFiltered,
            check_rst_window: false,
        }
    }

    /// NULL scan: RST → Closed, ICMP → Filtered, timeout → Open|Filtered.
    pub fn null_scan() -> Self {
        Self {
            on_syn_ack: None,
            on_rst: Some(PortState::Closed),
            on_icmp_unreachable: PortState::Filtered,
            on_no_response: PortState::OpenFiltered,
            check_rst_window: false,
        }
    }

    /// Xmas scan: RST → Closed, ICMP → Filtered, timeout → Open|Filtered.
    pub fn xmas_scan() -> Self {
        Self {
            on_syn_ack: None,
            on_rst: Some(PortState::Closed),
            on_icmp_unreachable: PortState::Filtered,
            on_no_response: PortState::OpenFiltered,
            check_rst_window: false,
        }
    }

    /// ACK scan: RST → Unfiltered, ICMP → Filtered, timeout → Filtered.
    /// Used for firewall rule mapping, not to determine open/closed.
    pub fn ack_scan() -> Self {
        Self {
            on_syn_ack: None,
            on_rst: Some(PortState::Unfiltered),
            on_icmp_unreachable: PortState::Filtered,
            on_no_response: PortState::Filtered,
            check_rst_window: false,
        }
    }

    /// Window scan: Like ACK but examines RST window size.
    /// RST with window > 0 → Open, window = 0 → Closed.
    /// ICMP → Filtered, timeout → Filtered.
    pub fn window_scan() -> Self {
        Self {
            on_syn_ack: None,
            on_rst: None, // Handled by check_rst_window logic
            on_icmp_unreachable: PortState::Filtered,
            on_no_response: PortState::Filtered,
            check_rst_window: true,
        }
    }

    /// Maimon scan: FIN/ACK. RST → Closed, ICMP → Filtered, timeout → Open|Filtered.
    pub fn maimon_scan() -> Self {
        Self {
            on_syn_ack: None,
            on_rst: Some(PortState::Closed),
            on_icmp_unreachable: PortState::Filtered,
            on_no_response: PortState::OpenFiltered,
            check_rst_window: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_scan_policy() {
        let p = ResponsePolicy::syn_scan();
        assert_eq!(p.on_syn_ack, Some(PortState::Open));
        assert_eq!(p.on_rst, Some(PortState::Closed));
        assert_eq!(p.on_icmp_unreachable, PortState::Filtered);
        assert_eq!(p.on_no_response, PortState::Filtered);
        assert!(!p.check_rst_window);
    }

    #[test]
    fn fin_scan_policy() {
        let p = ResponsePolicy::fin_scan();
        assert_eq!(p.on_syn_ack, None);
        assert_eq!(p.on_rst, Some(PortState::Closed));
        assert_eq!(p.on_no_response, PortState::OpenFiltered);
    }

    #[test]
    fn null_scan_policy() {
        let p = ResponsePolicy::null_scan();
        assert_eq!(p.on_syn_ack, None);
        assert_eq!(p.on_rst, Some(PortState::Closed));
        assert_eq!(p.on_no_response, PortState::OpenFiltered);
    }

    #[test]
    fn xmas_scan_policy() {
        let p = ResponsePolicy::xmas_scan();
        assert_eq!(p.on_syn_ack, None);
        assert_eq!(p.on_rst, Some(PortState::Closed));
        assert_eq!(p.on_no_response, PortState::OpenFiltered);
    }

    #[test]
    fn ack_scan_policy() {
        let p = ResponsePolicy::ack_scan();
        assert_eq!(p.on_syn_ack, None);
        assert_eq!(p.on_rst, Some(PortState::Unfiltered));
        assert_eq!(p.on_no_response, PortState::Filtered);
    }

    #[test]
    fn window_scan_policy() {
        let p = ResponsePolicy::window_scan();
        assert_eq!(p.on_syn_ack, None);
        assert_eq!(p.on_rst, None); // Handled by check_rst_window
        assert!(p.check_rst_window);
        assert_eq!(p.on_no_response, PortState::Filtered);
    }

    #[test]
    fn maimon_scan_policy() {
        let p = ResponsePolicy::maimon_scan();
        assert_eq!(p.on_syn_ack, None);
        assert_eq!(p.on_rst, Some(PortState::Closed));
        assert_eq!(p.on_no_response, PortState::OpenFiltered);
    }
}
