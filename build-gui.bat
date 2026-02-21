@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
set LIB=C:\npcap-sdk\Lib\x64;%LIB%
set CARGO_TARGET_DIR=C:\Users\stell\RustMapTarget

:: Build CLI first and copy as sidecar binary
echo Building CLI binary...
cd /d %~dp0
cargo build --release -p rustmap-cli --features tui
if errorlevel 1 (
    echo CLI build failed!
    exit /b 1
)

:: Copy CLI to sidecar binaries directory
if not exist "%~dp0rustmap-gui\binaries" mkdir "%~dp0rustmap-gui\binaries"
copy /Y "%CARGO_TARGET_DIR%\release\rustmap.exe" "%~dp0rustmap-gui\binaries\rustmap-x86_64-pc-windows-msvc.exe"

:: Build GUI
echo Building GUI...
cd /d %~dp0\rustmap-gui
cargo tauri %*
