use std::fmt;

/// TCP flag set for configuring outgoing probe packets.
///
/// Used by the generic `RawTcpScanner` to build packets with the
/// appropriate TCP flags for each scan type (SYN, FIN, NULL, Xmas, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl TcpFlags {
    /// No flags set (used as base for const construction).
    pub const NONE: Self = Self {
        syn: false,
        ack: false,
        fin: false,
        rst: false,
        psh: false,
        urg: false,
    };

    /// SYN scan: SYN flag only.
    pub const SYN: Self = Self {
        syn: true,
        ..Self::NONE
    };

    /// FIN scan: FIN flag only.
    pub const FIN: Self = Self {
        fin: true,
        ..Self::NONE
    };

    /// Xmas scan: FIN + PSH + URG ("lit up like a Christmas tree").
    pub const XMAS: Self = Self {
        fin: true,
        psh: true,
        urg: true,
        ..Self::NONE
    };

    /// ACK scan: ACK flag only.
    pub const ACK: Self = Self {
        ack: true,
        ..Self::NONE
    };

    /// Maimon scan: FIN + ACK.
    pub const MAIMON: Self = Self {
        fin: true,
        ack: true,
        ..Self::NONE
    };

    /// Returns true if no flags are set (NULL scan).
    pub fn is_empty(&self) -> bool {
        *self == Self::NONE
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        macro_rules! write_flag {
            ($flag:expr, $name:literal) => {
                if $flag {
                    if !first {
                        f.write_str("+")?;
                    }
                    f.write_str($name)?;
                    first = false;
                }
            };
        }
        write_flag!(self.syn, "SYN");
        write_flag!(self.ack, "ACK");
        write_flag!(self.fin, "FIN");
        write_flag!(self.rst, "RST");
        write_flag!(self.psh, "PSH");
        write_flag!(self.urg, "URG");
        if first {
            f.write_str("NONE")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_constant() {
        assert!(TcpFlags::SYN.syn);
        assert!(!TcpFlags::SYN.ack);
        assert!(!TcpFlags::SYN.fin);
        assert!(!TcpFlags::SYN.rst);
        assert!(!TcpFlags::SYN.psh);
        assert!(!TcpFlags::SYN.urg);
    }

    #[test]
    fn fin_constant() {
        assert!(!TcpFlags::FIN.syn);
        assert!(TcpFlags::FIN.fin);
        assert!(!TcpFlags::FIN.ack);
    }

    #[test]
    fn none_constant() {
        assert!(TcpFlags::NONE.is_empty());
        assert!(!TcpFlags::SYN.is_empty());
    }

    #[test]
    fn xmas_has_fin_psh_urg() {
        assert!(TcpFlags::XMAS.fin);
        assert!(TcpFlags::XMAS.psh);
        assert!(TcpFlags::XMAS.urg);
        assert!(!TcpFlags::XMAS.syn);
        assert!(!TcpFlags::XMAS.ack);
        assert!(!TcpFlags::XMAS.rst);
    }

    #[test]
    fn ack_constant() {
        assert!(TcpFlags::ACK.ack);
        assert!(!TcpFlags::ACK.syn);
        assert!(!TcpFlags::ACK.fin);
    }

    #[test]
    fn maimon_has_fin_ack() {
        assert!(TcpFlags::MAIMON.fin);
        assert!(TcpFlags::MAIMON.ack);
        assert!(!TcpFlags::MAIMON.syn);
        assert!(!TcpFlags::MAIMON.psh);
    }

    #[test]
    fn display_syn() {
        assert_eq!(TcpFlags::SYN.to_string(), "SYN");
    }

    #[test]
    fn display_none() {
        assert_eq!(TcpFlags::NONE.to_string(), "NONE");
    }

    #[test]
    fn display_xmas() {
        assert_eq!(TcpFlags::XMAS.to_string(), "FIN+PSH+URG");
    }

    #[test]
    fn display_maimon() {
        assert_eq!(TcpFlags::MAIMON.to_string(), "ACK+FIN");
    }

    #[test]
    fn display_ack() {
        assert_eq!(TcpFlags::ACK.to_string(), "ACK");
    }

    #[test]
    fn equality() {
        assert_eq!(TcpFlags::SYN, TcpFlags::SYN);
        assert_ne!(TcpFlags::SYN, TcpFlags::FIN);
        assert_ne!(TcpFlags::NONE, TcpFlags::SYN);
    }
}
