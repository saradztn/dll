@echo off
REM ===========================================================================
REM  build_mingw.bat - build NRTH_audit.dll + nrth_audit_cli.exe with MinGW-w64
REM ===========================================================================
REM  Use the toolchain that matches the bitness you want:
REM    i686-w64-mingw32-g++    -> 32-bit  (the original module's architecture)
REM    x86_64-w64-mingw32-g++  -> 64-bit
REM  Adjust CXX below, or put the desired bin/ directory first in PATH.
REM
REM  Outputs:  dist\NRTH_audit.dll, dist\NRTH_audit.lib, dist\nrth_audit_cli.exe
REM ===========================================================================
setlocal
cd /d "%~dp0"

set CXX=g++
where %CXX% >nul 2>&1
if errorlevel 1 (
    echo [!] %CXX% not found in PATH. Install MinGW-w64 or edit CXX= above.
    exit /b 1
)

if not exist dist mkdir dist

echo === NRTH_audit.dll ===
%CXX% -O2 -s -DNRTH_AUDIT_STATIC -shared -static-libgcc -static-libstdc++ ^
      -o dist\NRTH_audit.dll nrth_audit.cpp nrth_audit.def ^
      -Wl,--out-implib,dist\NRTH_audit.lib
if errorlevel 1 goto :fail

echo === nrth_audit_cli.exe ===
%CXX% -O2 -s -static -static-libgcc -static-libstdc++ ^
      -o dist\nrth_audit_cli.exe tools\nrth_audit_cli.c nrth_audit.cpp
if errorlevel 1 goto :fail

echo.
echo === smoke test ===
dist\nrth_audit_cli.exe version
dist\nrth_audit_cli.exe selftest
if errorlevel 1 goto :fail

echo.
echo [*] done - artifacts in dist\
exit /b 0

:fail
echo.
echo [!] build failed.
exit /b 1
