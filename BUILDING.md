# Building RustMap from Source

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Rust | 1.85+ | Edition 2024, install via [rustup](https://rustup.rs) |
| C/C++ compiler | MSVC (Windows) / gcc (Linux) / Xcode CLT (macOS) | For native dependencies |
| Npcap SDK | 1.13+ | Windows only, for raw packet access |
| libpcap-dev | Latest | Linux only (`apt install libpcap-dev`) |
| Node.js | 20+ | GUI only |
| Tauri CLI | 2.x | GUI only (`cargo install tauri-cli --locked`) |

## Windows

### 1. Install Build Tools

Install [Visual Studio 2019/2022 Build Tools](https://visualstudio.microsoft.com/downloads/) with the "Desktop development with C++" workload.

### 2. Install Npcap

Download and install [Npcap](https://npcap.com/#download) (runtime) and the [Npcap SDK](https://npcap.com/#download) (development headers).

Extract the SDK to `C:\npcap-sdk\` so that `C:\npcap-sdk\Lib\x64\` contains `Packet.lib` and `wpcap.lib`.

### 3. Install Rust

```powershell
# Install rustup (if not already installed)
winget install Rustlang.Rustup

# Ensure you have the right toolchain
rustup default stable
rustup update
```

### 4. Build the CLI

Use `build.bat` which sets up the MSVC environment and Npcap library paths:

```batch
:: Build all crates (excluding GUI)
build.bat build --workspace --exclude rustmap-gui

:: Run tests
build.bat test --workspace --exclude rustmap-gui

:: Build release binary with all default features (watch + API + TUI)
build.bat build --release -p rustmap-cli --features tui

:: Build with cloud discovery support
build.bat build --release -p rustmap-cli --features "tui,cloud"

:: Run clippy
build.bat clippy --workspace --exclude rustmap-gui -- -D warnings

:: Run cargo audit
build.bat audit
```

The CLI binary is at `target\release\rustmap.exe`.

> **Note:** If your project is in a OneDrive-synced directory, Windows Application Control may block test binaries. Set `CARGO_TARGET_DIR` to a local path:
> ```batch
> set CARGO_TARGET_DIR=C:\Users\%USERNAME%\RustMapTarget
> build.bat build --workspace --exclude rustmap-gui
> ```

### 5. Build the GUI (optional)

The GUI requires Node.js and the Tauri CLI:

```batch
:: Install Tauri CLI
build.bat install tauri-cli --locked

:: Install frontend dependencies
cd rustmap-gui\frontend
npm install
npm run build
cd ..\..

:: Build the GUI application
build-gui.bat build
```

The installer is at `C:\Users\<you>\RustMapTarget\release\bundle\nsis\RustMap_0.1.0_x64-setup.exe`.

> **Note:** The GUI build uses `CARGO_TARGET_DIR=C:\Users\<you>\RustMapTarget` because Windows Application Control policies may block build scripts from executing within OneDrive-synced directories. The `build-gui.bat` script handles this automatically.

## Linux

### 1. Install Dependencies

```bash
# Debian/Ubuntu — CLI only
sudo apt install build-essential libpcap-dev

# Debian/Ubuntu — CLI + GUI
sudo apt install build-essential libpcap-dev \
  libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev \
  libsoup-3.0-dev libjavascriptcoregtk-4.1-dev

# Fedora/RHEL — CLI only
sudo dnf install gcc libpcap-devel

# Fedora/RHEL — CLI + GUI
sudo dnf install gcc libpcap-devel \
  webkit2gtk4.1-devel gtk3-devel \
  libappindicator-gtk3-devel librsvg2-devel

# Arch — CLI only
sudo pacman -S base-devel libpcap

# Arch — CLI + GUI
sudo pacman -S base-devel libpcap \
  webkit2gtk-4.1 gtk3 libappindicator-gtk3 librsvg
```

### 2. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 3. Build the CLI

```bash
# Build all crates (excluding GUI)
cargo build --workspace --exclude rustmap-gui

# Run tests
cargo test --workspace --exclude rustmap-gui

# Build release binary with TUI
cargo build --release -p rustmap-cli --features tui

# Build with cloud discovery support
cargo build --release -p rustmap-cli --features "tui,cloud"

# Run clippy
cargo clippy --workspace --exclude rustmap-gui -- -D warnings
```

The CLI binary is at `target/release/rustmap`.

### 4. Build the GUI (optional)

```bash
# Install Tauri CLI
cargo install tauri-cli --locked

# Build frontend
cd rustmap-gui/frontend
npm install && npm run build
cd ../..

# Build GUI (creates .AppImage and .deb)
cd rustmap-gui && cargo tauri build
```

Output:
- AppImage: `target/release/bundle/appimage/rustmap_0.1.0_amd64.AppImage`
- Debian package: `target/release/bundle/deb/rustmap_0.1.0_amd64.deb`

## macOS

### 1. Install Dependencies

```bash
# Install Xcode Command Line Tools (provides C compiler)
xcode-select --install

# libpcap is included with macOS — no additional packages needed for CLI
```

### 2. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 3. Build the CLI

```bash
# Build all crates (excluding GUI)
cargo build --workspace --exclude rustmap-gui

# Run tests
cargo test --workspace --exclude rustmap-gui

# Build release binary with TUI
cargo build --release -p rustmap-cli --features tui

# Build with cloud discovery support
cargo build --release -p rustmap-cli --features "tui,cloud"
```

The CLI binary is at `target/release/rustmap`.

### 4. Build the GUI (optional)

```bash
# Install Node.js (via Homebrew)
brew install node

# Install Tauri CLI
cargo install tauri-cli --locked

# Build frontend
cd rustmap-gui/frontend
npm install && npm run build
cd ../..

# Build GUI (creates .dmg)
cd rustmap-gui && cargo tauri build
```

Output: `target/release/bundle/dmg/RustMap_0.1.0_<arch>.dmg`

Works on both Intel (x86_64) and Apple Silicon (arm64) Macs — builds for the native architecture.

## Feature Flags

### CLI Features (`rustmap-cli`)

| Feature | Default | Description |
|---------|---------|-------------|
| `watch` | enabled | Watch/continuous mode (`--watch`) |
| `api` | enabled | REST API server (`--api`) |
| `tui` | enabled | Interactive terminal UI (`--tui`) |
| `wasm` | disabled | WebAssembly script support (wasmtime) |
| `cloud-aws` | disabled | AWS EC2 asset discovery |
| `cloud-azure` | disabled | Azure VM asset discovery |
| `cloud-gcp` | disabled | GCP Compute Engine asset discovery |
| `cloud` | disabled | All cloud providers |

Build examples:

```bash
# Default features (watch + API + TUI)
cargo build --release -p rustmap-cli --features tui

# Minimal binary (no TUI, no API, no watch)
cargo build --release -p rustmap-cli --no-default-features

# With cloud discovery
cargo build --release -p rustmap-cli --features "tui,cloud"

# With WASM script support
cargo build --release -p rustmap-cli --features "tui,wasm"

# Everything enabled
cargo build --release -p rustmap-cli --features "tui,cloud,wasm"
```

### Script Engine Features (`rustmap-script`)

| Feature | Default | Description |
|---------|---------|-------------|
| `wasm` | disabled | WebAssembly sandbox via wasmtime |

### Vulnerability Features (`rustmap-vuln`)

| Feature | Default | Description |
|---------|---------|-------------|
| `update` | enabled | CVE database updates from NVD API |

### Cloud Features (`rustmap-cloud`)

| Feature | Default | Description |
|---------|---------|-------------|
| `aws` | disabled | AWS EC2 discovery |
| `azure` | disabled | Azure VM discovery |
| `gcp` | disabled | GCP Compute discovery |

## Python Bindings

The `rustmap-python` crate provides PyO3-based Python bindings. Build with [maturin](https://www.maturin.rs/):

```bash
# Install maturin
pip install maturin

# Build and install into current Python environment
cd rustmap-python
maturin develop --release

# Build a wheel for distribution
maturin build --release
```

Requires Python 3.9+ (uses abi3 stable ABI for broad compatibility).

## Project Layout

```
build.bat            Windows CLI build wrapper (sets MSVC + Npcap env)
build-gui.bat        Windows GUI build wrapper (adds CARGO_TARGET_DIR)
Cargo.toml           Workspace root (16 crates, edition 2024, resolver 3)
rustmap-types/       Shared type definitions
rustmap-packet/      Raw packet I/O (pcap)
rustmap-timing/      Timing and congestion control
rustmap-scan/        Scanner implementations (TCP, UDP, SCTP, discovery, traceroute)
rustmap-detect/      Service and OS detection, QUIC/HTTP3 probing
rustmap-script/      Lua + Python + WASM scripting engine
  scripts/           54 built-in scripts (.lua, .py)
rustmap-output/      Output formatters (9 formats) + topology graph export
rustmap-core/        Scan engine orchestration
rustmap-db/          SQLite storage (scan history, checkpoints, diff, profiles, network profiling)
rustmap-vuln/        Vulnerability correlation (CVE database + NVD updates)
rustmap-geoip/       GeoIP and ASN enrichment (MaxMind GeoLite2)
rustmap-cloud/       Cloud asset discovery (AWS, Azure, GCP)
rustmap-api/         REST API server (axum + WebSocket)
rustmap-python/      Python bindings (PyO3, maturin)
rustmap-cli/         CLI binary (clap, TUI, watch mode, profiles)
rustmap-gui/         Tauri 2 GUI
  frontend/          Svelte 5 + TypeScript frontend
  tauri.conf.json    Tauri configuration
```

## Test Suite

The workspace contains 793+ tests across all crates:

```bash
# Run all tests (excluding GUI, which needs frontend build)
cargo test --workspace --exclude rustmap-gui

# Run tests for a specific crate
cargo test -p rustmap-scan
cargo test -p rustmap-api
cargo test -p rustmap-script
cargo test -p rustmap-db
cargo test -p rustmap-detect
cargo test -p rustmap-vuln

# Run GUI tests (requires frontend build first)
cd rustmap-gui/frontend && npm run build && cd ../..
cargo test -p rustmap-gui

# Run Python binding tests
cd rustmap-python && maturin develop && pytest
```

On Windows, use `build.bat` for all cargo commands to ensure the MSVC environment and Npcap SDK paths are set.

## CI/CD

The project uses GitHub Actions for continuous integration and release builds.

### Test Workflow (`.github/workflows/test.yml`)

Runs on every push to `main` and on pull requests:
- **rustfmt** check
- **Clippy** lint (warnings as errors)
- **Tests** on Windows and Linux
- **GUI build check** on Windows

### Release Workflow (`.github/workflows/release.yml`)

Triggered by pushing a version tag (e.g., `git tag v0.1.0 && git push origin v0.1.0`):

| Job | Runner | Output |
|-----|--------|--------|
| CLI (Windows x86_64) | windows-latest | `rustmap-windows-x86_64.exe` |
| CLI (Linux x86_64) | ubuntu-latest | `rustmap-linux-x86_64` |
| CLI (macOS x86_64) | macos-13 | `rustmap-macos-x86_64` |
| CLI (macOS arm64) | macos-latest | `rustmap-macos-arm64` |
| GUI (Windows) | windows-latest | NSIS installer (`.exe`) |
| GUI (Linux) | ubuntu-latest | AppImage + `.deb` |
| GUI (macOS x86_64) | macos-13 | `.dmg` |
| GUI (macOS arm64) | macos-latest | `.dmg` |

All 8 build jobs run in parallel, then a release job collects artifacts and creates a GitHub Release with auto-generated release notes.

All CLI builds include the `tui` feature for the interactive terminal UI.

## Troubleshooting

### `vswhere.exe is not recognized`
This warning is harmless and can be ignored. It comes from the MSVC environment initialization.

### `An Application Control policy has blocked this file`
This occurs when building from an OneDrive-synced directory on Windows. Use `build-gui.bat` which sets `CARGO_TARGET_DIR` to a local path outside OneDrive, or set the env var manually:
```batch
set CARGO_TARGET_DIR=C:\Users\%USERNAME%\RustMapTarget
```

### `insufficient privileges for SYN scan`
SYN, UDP, SCTP, and discovery scans require raw socket access. Run as Administrator (Windows) or root/`CAP_NET_RAW` (Linux). TCP Connect scans (`-s T`) work without elevated privileges.

On Linux, you can grant raw socket capability without root:
```bash
sudo setcap cap_net_raw=ep target/release/rustmap
```

### `Packet.lib not found` / linker errors
Ensure the Npcap SDK is extracted to `C:\npcap-sdk\` and that `build.bat` is used (it sets the `LIB` path).

### GUI build fails with `tauri-cli not found`
Install the Tauri CLI:
```bash
cargo install tauri-cli --locked
```

### Frontend build errors
Ensure Node.js 20+ is installed and frontend dependencies are up to date:
```bash
cd rustmap-gui/frontend
rm -rf node_modules
npm install
npm run build
```

### `libpcap not found` (Linux)
Install the development package:
```bash
# Debian/Ubuntu
sudo apt install libpcap-dev

# Fedora/RHEL
sudo dnf install libpcap-devel
```

### GUI build fails on Linux with missing GTK/WebKit
Install the Tauri system dependencies:
```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev \
  libsoup-3.0-dev libjavascriptcoregtk-4.1-dev
```

### Cargo audit reports vulnerabilities
Run `cargo audit` to check for known vulnerabilities in dependencies. The project targets zero known vulnerabilities:
```bash
cargo audit
```

If `cargo audit` is not installed: `cargo install cargo-audit`.
