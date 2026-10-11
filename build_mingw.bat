@echo off
REM ===========================================================================
REM  build_mingw.bat - build NRTH_audit.dll + nrth_audit_cli.exe with MinGW-w64
REM ===========================================================================
REM  The compiler is auto-detected in this order:
REM      i686-w64-mingw32-g++     -> 32-bit (the original module's architecture)
REM      x86_64-w64-mingw32-g++   -> 64-bit
REM      mingw32-g++ / g++
REM  i.e. a plain "g++" in PATH, a MinGW install directory that is not on PATH,
REM  or a Chocolatey/MSYS2/Scoop layout all work without editing this file.
REM
REM  usage:  build_mingw.bat [compiler]
REM          build_mingw.bat C:\msys64\mingw32\bin\i686-w64-mingw32-g++.exe
REM
REM  outputs: dist\NRTH_audit.dll      (32-bit compiler)
REM           dist\NRTH_audit_x64.dll  (64-bit compiler)
REM           dist\nrth_audit_cli.exe / nrth_audit_cli_x64.exe
REM           dist\NRTH_audit*.lib     (import library)
REM  Override the output stem with OUTSUFFIX=x64 if the name heuristic is wrong.
REM ===========================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "CXX=%~1"
if defined CXX goto :have_cxx
call :detect_compiler
if not defined CXX (
    echo [!] no MinGW-w64 g++ found.
    echo     Install MinGW-w64, or pass the compiler explicitly:
    echo         build_mingw.bat C:\path\to\i686-w64-mingw32-g++.exe
    exit /b 1
)

:have_cxx
REM make sure the compiler's own bin directory is first in PATH (it pulls in its
REM runtime DLLs during the link and smoke test)
for %%P in ("%CXX%") do set "CXXDIR=%%~dpP"
set "PATH=%CXXDIR%;%PATH%"

REM 32-bit toolchains are named i686-w64-mingw32-g++ or mingw32-g++. Note that
REM "mingw32" alone is NOT a 32-bit marker: x86_64-w64-mingw32-g++ contains it
REM too, so only i686 / the exact mingw32-g++ stem count as 32-bit here.
set "SUFFIX=_x64"
echo %CXX% | findstr /i "i686 mingw32-g++" >nul && set "SUFFIX="
if defined OUTSUFFIX set "SUFFIX=%OUTSUFFIX%"

if not exist dist mkdir dist

echo [*] compiler: %CXX%
"%CXX%" --version | findstr /i "g++ gcc mingw" | findstr /n "." | findstr "^1:"

echo.
echo === NRTH_audit%SUFFIX%.dll ===
"%CXX%" -O2 -s -DNRTH_AUDIT_STATIC -shared -static-libgcc -static-libstdc++ ^
      -o dist\NRTH_audit%SUFFIX%.dll nrth_audit.cpp nrth_audit.def ^
      -Wl,--out-implib,dist\NRTH_audit%SUFFIX%.lib
if errorlevel 1 goto :fail

echo.
echo === nrth_audit_cli%SUFFIX%.exe ===
"%CXX%" -O2 -s -static -static-libgcc -static-libstdc++ ^
      -o dist\nrth_audit_cli%SUFFIX%.exe tools\nrth_audit_cli.c nrth_audit.cpp
if errorlevel 1 goto :fail

echo.
echo === smoke test ===
dist\nrth_audit_cli%SUFFIX%.exe version
dist\nrth_audit_cli%SUFFIX%.exe selftest
if errorlevel 1 goto :fail

echo.
echo [*] done - artifacts in dist\
exit /b 0

:fail
echo.
echo [!] build failed.
exit /b 1

REM ---------------------------------------------------------------- helpers --
:detect_compiler
for %%N in (i686-w64-mingw32-g++ x86_64-w64-mingw32-g++ mingw32-g++ g++) do (
    for /f "delims=" %%W in ('where %%N 2^>nul') do (
        if not defined CXX set "CXX=%%W"
    )
    if defined CXX goto :eof
)
REM not on PATH - probe the usual install roots
for %%R in (
    "C:\ProgramData\mingw64"
    "C:\ProgramData\chocolatey"
    "C:\tools"
    "C:\mingw64"
    "C:\mingw32"
    "C:\msys64"
    "C:\Program Files\mingw64"
    "%USERPROFILE%\scoop\apps"
) do (
    if exist %%R (
        for %%N in (i686-w64-mingw32-g++.exe x86_64-w64-mingw32-g++.exe mingw32-g++.exe g++.exe) do (
            for /f "delims=" %%F in ('dir /b /s "%%~R\%%N" 2^>nul') do (
                if not defined CXX set "CXX=%%F"
            )
        )
    )
    if defined CXX goto :eof
)
goto :eof
