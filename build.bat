@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
set LIB=C:\npcap-sdk\Lib\x64;%LIB%
cd /d %~dp0
cargo %*
