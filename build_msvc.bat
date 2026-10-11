@echo off
REM ===========================================================================
REM  build_msvc.bat - build NRTH_audit.dll + nrth_audit_cli.exe with MSVC
REM ===========================================================================
REM  Run from the Visual Studio developer prompt that matches the bitness you
REM  want:  "x86 Native Tools Command Prompt for VS"  -> 32-bit DLL (the target
REM         the original module used), or "x64 Native Tools..." -> 64-bit.
REM
REM  Outputs:  dist\NRTH_audit.dll        (exports 23 ordinals from nrth_audit.def)
REM            dist\NRTH_audit.lib        (import library for C/C++ callers)
REM            dist\nrth_audit_cli.exe    (console front-end, self-contained)
REM
REM  /DNRTH_AUDIT_STATIC keeps the definitions free of dllexport; the export
REM  table (with ordinals @1..@23) comes from nrth_audit.def, so the binary
REM  matches the documented contract exactly.
REM ===========================================================================
setlocal
cd /d "%~dp0"

where cl >nul 2>&1
if errorlevel 1 (
    echo [!] cl.exe not found in PATH.
    echo     Open an "x86 Native Tools Command Prompt for VS" and re-run this script.
    exit /b 1
)

if not exist dist   mkdir dist
if not exist build\msvc mkdir build\msvc

echo === NRTH_audit.dll ===
cl /nologo /O2 /W3 /EHsc /MT /DNRTH_AUDIT_STATIC /D_CRT_SECURE_NO_WARNINGS ^
   /LD nrth_audit.cpp /Fo:build\msvc\ /Fe:dist\NRTH_audit.dll ^
   /link /DEF:nrth_audit.def /DLL /IMPLIB:dist\NRTH_audit.lib /PDB:dist\NRTH_audit.pdb
if errorlevel 1 goto :fail

echo === nrth_audit_cli.exe ===
REM /DNRTH_AUDIT_STATIC: the front-end links the module into the executable,
REM so the API must not be declared dllimport.
cl /nologo /O2 /W3 /MT /DNRTH_AUDIT_STATIC /D_CRT_SECURE_NO_WARNINGS ^
   tools\nrth_audit_cli.c nrth_audit.cpp /Fo:build\msvc\ /Fe:dist\nrth_audit_cli.exe
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
