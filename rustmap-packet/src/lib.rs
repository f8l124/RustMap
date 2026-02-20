pub mod build;
pub mod capture;
pub mod fragment;
pub mod os_probes;
pub mod parse;
pub mod platform;
pub mod privilege;
pub mod rst_suppress;
pub mod tcp_flags;
pub mod traits;
pub mod udp_payloads;

#[cfg(windows)]
pub mod net_windows;
#[cfg(target_os = "linux")]
pub mod sender_linux;
#[cfg(windows)]
pub mod sender_windows;

#[cfg(target_os = "linux")]
mod privilege_linux;
#[cfg(windows)]
mod privilege_windows;

pub use capture::{
    AsyncCapture, CaptureConfig, fixed_port_bpf_filter, list_interfaces, udp_bpf_filter,
    udp_fixed_port_bpf_filter,
};
pub use fragment::fragment_ipv4_packet;
pub use platform::{create_capture, create_sender};
#[cfg(windows)]
pub use privilege::npcap_installed;
pub use privilege::{PacketError, PrivilegeLevel, check_privileges};
pub use rst_suppress::RstSuppressGuard;
pub use tcp_flags::TcpFlags;
pub use traits::{CapturedResponse, PacketReceiver, PacketSender, ResponseType, rand_seq};
