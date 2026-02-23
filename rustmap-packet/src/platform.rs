use std::net::IpAddr;

use crate::capture::{AsyncCapture, CaptureConfig};
use crate::privilege::PacketError;
use crate::traits::PacketSender;

/// Create a platform-appropriate packet sender.
///
/// - Linux: raw socket with IP_HDRINCL
/// - Windows: Npcap packet injection
pub fn create_sender(target_ip: IpAddr) -> Result<Box<dyn PacketSender>, PacketError> {
    create_sender_with_options(target_ip, None)
}

/// Create a packet sender with optional MAC spoofing.
pub fn create_sender_with_options(
    target_ip: IpAddr,
    spoof_mac: Option<[u8; 6]>,
) -> Result<Box<dyn PacketSender>, PacketError> {
    #[cfg(target_os = "linux")]
    {
        let _ = spoof_mac; // MAC spoofing not applicable to raw sockets
        use crate::sender_linux::RawSocketSender;
        let sender = RawSocketSender::new(get_local_ip(target_ip)?)?;
        Ok(Box::new(sender))
    }
    #[cfg(windows)]
    {
        use crate::sender_windows::NpcapSender;
        let mut sender = NpcapSender::new(target_ip)?;
        if let Some(mac) = spoof_mac {
            sender.set_spoof_mac(mac);
        }
        Ok(Box::new(sender))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (target_ip, spoof_mac);
        Err(PacketError::SendFailed(
            "raw packet sending not supported on this platform".into(),
        ))
    }
}

/// Create an async packet capture for SYN scan responses.
pub fn create_capture(config: CaptureConfig) -> Result<AsyncCapture, PacketError> {
    AsyncCapture::start(config)
}

/// Get the local source IP for reaching a target.
/// Used on Linux where we need to specify src_ip for raw sockets.
#[cfg(target_os = "linux")]
fn get_local_ip(target: IpAddr) -> Result<IpAddr, PacketError> {
    // Connect a UDP socket to determine the outbound IP
    // (no actual traffic is sent — just routing lookup)
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|_e| PacketError::NoInterface)?;
    let target_addr = std::net::SocketAddr::new(target, 80);
    socket
        .connect(target_addr)
        .map_err(|_e| PacketError::NoInterface)?;
    let local_addr = socket.local_addr().map_err(|_e| PacketError::NoInterface)?;
    Ok(local_addr.ip())
}
