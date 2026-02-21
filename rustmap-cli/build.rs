fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        // Delay-load Npcap DLLs so the binary can start without Npcap installed.
        // Without delay-loading, Windows refuses to launch the process at all
        // (STATUS_DLL_NOT_FOUND / 0xc0000135) if wpcap.dll is absent.
        // With delay-loading, the DLL is only loaded when a pcap function is
        // first called, allowing us to show a helpful setup prompt instead.
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:Packet.dll");
        println!("cargo:rustc-link-lib=delayimp");
    }
}
