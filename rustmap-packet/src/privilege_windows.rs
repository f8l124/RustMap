use crate::privilege::PrivilegeLevel;

/// Check whether the Npcap runtime is installed.
///
/// Npcap installs `wpcap.dll` into `%SystemRoot%\System32\Npcap\`.
/// If this DLL is absent, raw packet capture/injection will fail at runtime.
pub fn npcap_installed() -> bool {
    let sys32 = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let npcap_dll = std::path::Path::new(&sys32).join(r"System32\Npcap\wpcap.dll");
    npcap_dll.exists()
}

/// Check if the current process is running elevated (as Administrator) on Windows.
///
/// Uses the Win32 API: OpenProcessToken + GetTokenInformation(TokenElevation).
pub fn check() -> PrivilegeLevel {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, FALSE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == FALSE {
            return PrivilegeLevel::Unprivileged;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length: u32 = 0;
        let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

        let result = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut return_length,
        );

        CloseHandle(token);

        if result != FALSE && elevation.TokenIsElevated != 0 {
            PrivilegeLevel::Full
        } else {
            PrivilegeLevel::Unprivileged
        }
    }
}
