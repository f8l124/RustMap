# Changelog

All notable changes to RustMap are documented here.

## [Unreleased]

### Added
- **Windows first-run Npcap setup wizard** — when Npcap is not installed, RustMap interactively offers to download and install it, with browser fallback if the download fails
- **Delay-loaded Npcap DLLs on Windows** — `wpcap.dll` and `Packet.dll` are delay-loaded via MSVC linker flags so the binary can start without Npcap installed (graceful prompt instead of `STATUS_DLL_NOT_FOUND` crash)

### Changed
- **CI test matrix expanded** — tests now run on Windows, Linux, and macOS; GUI checks run on all three platforms
- Windows CI excludes pcap-dependent crates from test execution (Npcap runtime cannot be installed in headless CI)

## [0.1.0] - 2026-02-19

### Added

Initial commit