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
#[cfg(windows)]
pub mod sender_windows;
#[cfg(unix)]
pub mod sender_linux;

#[cfg(windows)]
mod privilege_windows;
#[cfg(unix)]
mod privilege_linux;

pub use capture::{AsyncCapture, CaptureConfig, fixed_port_bpf_filter, list_interfaces, udp_bpf_filter, udp_fixed_port_bpf_filter};
pub use platform::{create_capture, create_sender};
pub use privilege::{check_privileges, PacketError, PrivilegeLevel};
#[cfg(windows)]
pub use privilege::npcap_installed;
pub use fragment::fragment_ipv4_packet;
pub use rst_suppress::RstSuppressGuard;
pub use tcp_flags::TcpFlags;
pub use traits::{CapturedResponse, PacketReceiver, PacketSender, ResponseType, rand_seq};
