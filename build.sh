#!/usr/bin/env bash
# ============================================================================
# build.sh — build the NRTH/NVX defensive audit module (DLL) and its console
#            front-end (EXE) for 32-bit and 64-bit Windows.
# ============================================================================
# The module is pure C/C++ with no third-party dependencies, so it can be built
# either
#   (a) natively on Windows   -> build_msvc.bat / build_mingw.bat, or
#   (b) cross-compiled anywhere with zig (this script; no Windows required).
#
# usage:
#   ./build.sh              build the DLLs and the EXE front-ends into dist/
#   ./build.sh dll          build only NRTH_audit.dll / NRTH_audit_x64.dll
#   ./build.sh exe          build only nrth_audit_cli.exe / _x64.exe
#   ./build.sh linux        native test build (dist/linux/nrth_audit_cli)
#   ./build.sh test         native test build + fixtures + full test suite
#   ./build.sh clean        remove dist/ and build/
#
# environment:
#   ZIG=/path/to/zig        use a specific zig binary
#   ARCHES="x86 x64"        limit the Windows target list
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"
BUILD="$ROOT/build"
ARCHES="${ARCHES:-x86 x64}"

# --- locate a compiler ------------------------------------------------------
find_zig() {
    if [ -n "${ZIG:-}" ] && [ -x "${ZIG}" ]; then echo "$ZIG"; return 0; fi
    if command -v zig >/dev/null 2>&1; then command -v zig; return 0; fi
    # pip-installed ziglang wheel ships the compiler as a module
    if python3 -c "import ziglang" >/dev/null 2>&1; then echo "python3 -m ziglang"; return 0; fi
    return 1
}

need_zig() {
    if ! ZIGBIN="$(find_zig)"; then
        cat >&2 <<'EOF'
[!] no C/C++ cross-compiler found.

    Option 1 (no Windows required):   pip install --user ziglang   && ./build.sh
    Option 2 (Debian/Ubuntu):         sudo apt install mingw-w64   && ./build.sh
    Option 3 (on Windows):            build_msvc.bat   (Visual Studio)
                                      build_mingw.bat  (MinGW-w64)
EOF
        exit 1
    fi
}

cc_win() { # $1 = target triple, rest = clang arguments
    local triple="$1"; shift
    need_zig
    # -DNRTH_AUDIT_STATIC keeps the definitions free of dllexport/dllimport; the
    # export table (and its ordinals) comes from nrth_audit.def, matching the
    # original module's contract exactly.
    $ZIGBIN c++ -target "$triple" -O2 -s -fno-exceptions -fno-rtti \
        -DNRTH_AUDIT_STATIC -I"$ROOT" "$@"
}

triple_of() {
    case "$1" in
        x86)  echo "x86-windows-gnu" ;;
        x64)  echo "x86_64-windows-gnu" ;;
        *) echo "[!] unknown arch '$1' (use x86 / x64)" >&2; exit 2 ;;
    esac
}

# --- helpers ----------------------------------------------------------------
verify_exports() { # $1 = dll
    command -v objdump >/dev/null 2>&1 || return 0
    local n
    n="$(objdump -p "$1" | sed -n '/\[Ordinal\/Name Pointer\] Table/,/^$/p' | grep -c '\]  *Nrth' || true)"
    echo "    exports resolved: ${n}/23"
    [ "$n" -eq 23 ] || { echo "[!] export table incomplete in $1" >&2; exit 1; }
}

banner() { printf '\n=== %s ===\n' "$1"; }

# --- targets ----------------------------------------------------------------
build_dll() {
    mkdir -p "$DIST"
    for a in $ARCHES; do
        local t out implib
        t="$(triple_of "$a")"
        out="$DIST/$([ "$a" = x86 ] && echo NRTH_audit.dll || echo "NRTH_audit_${a}.dll")"
        # keep an import library next to the DLL so C/C++ callers can link
        implib="${out%.dll}.lib"
        banner "DLL ($a, $t)"
        cc_win "$t" -shared -o "$out" "$ROOT/nrth_audit.cpp" "$ROOT/nrth_audit.def" \
               -Wl,--out-implib,"$implib"
        ls -l "$out" "$implib"
        verify_exports "$out"
    done
}

build_exe() {
    mkdir -p "$DIST"
    for a in $ARCHES; do
        local t out
        t="$(triple_of "$a")"
        out="$DIST/$([ "$a" = x86 ] && echo nrth_audit_cli.exe || echo "nrth_audit_cli_${a}.exe")"
        banner "console front-end ($a, $t)"
        cc_win "$t" -o "$out" "$ROOT/tools/nrth_audit_cli.c" "$ROOT/nrth_audit.cpp"
        ls -l "$out"
    done
}

build_linux() {
    mkdir -p "$DIST/linux"
    banner "native test build (this machine)"
    if command -v g++ >/dev/null 2>&1; then
        g++ -O2 -Wall -Wextra -o "$DIST/linux/nrth_audit_cli" \
            "$ROOT/tools/nrth_audit_cli.c" "$ROOT/nrth_audit.cpp"
        g++ -O2 -shared -fPIC -o "$DIST/linux/NRTH_audit.so" "$ROOT/nrth_audit.cpp"
    else
        need_zig
        $ZIGBIN c++ -O2 -o "$DIST/linux/nrth_audit_cli" \
            "$ROOT/tools/nrth_audit_cli.c" "$ROOT/nrth_audit.cpp"
        $ZIGBIN c++ -O2 -shared -fPIC -o "$DIST/linux/NRTH_audit.so" "$ROOT/nrth_audit.cpp"
    fi
    ls -l "$DIST/linux"
}

case "${1:-all}" in
    all)   build_dll; build_exe ;;
    dll)   build_dll ;;
    exe)   build_exe ;;
    linux) build_linux ;;
    test)  build_linux; "$ROOT/tools/run_tests.sh" ;;
    clean) rm -rf "$DIST" "$BUILD"; echo "[*] removed dist/ and build/" ;;
    *)     sed -n '2,22p' "$0"; exit 2 ;;
esac
echo
echo "[*] done."
