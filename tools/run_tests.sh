#!/usr/bin/env bash
# ============================================================================
# run_tests.sh — behavioural test suite for the NRTH/NVX defensive audit module
# ============================================================================
# Builds the module natively (Linux/macOS), generates synthetic PE fixtures with
# tools/make_test_image.py, then asserts what `audit`, `diff`, `hidden`, `scan`,
# `prologue`, `xor` and `selftest` must report and which exit code each returns.
#
# The fixtures contain only the catalogue's published pattern bytes - no code
# from any real module - so the suite is safe to run anywhere and in CI.
#
# usage: tools/run_tests.sh [path-to-cli]     (default: dist/linux/nrth_audit_cli)
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_ARG="${1:-}"
CLI="${CLI_ARG:-$ROOT/build/nrth_audit_cli_linux}"
WORK="$ROOT/build/test"
PASS=0
FAIL=0

say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf '  [ ok ] %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

# check <name> <expected-exit> <needle|-> <cmd...>
check() {
    local name="$1" want="$2" needle="$3"; shift 3
    local out rc
    out="$("$@" 2>&1)"; rc=$?
    if [ "$rc" -ne "$want" ]; then
        bad "$name (exit $rc, expected $want)"; printf '%s\n' "$out" | sed 's/^/         | /' | head -6
        return
    fi
    if [ "$needle" != "-" ] && ! printf '%s' "$out" | grep -q -- "$needle"; then
        bad "$name (output lacks '$needle')"; printf '%s\n' "$out" | sed 's/^/         | /' | head -6
        return
    fi
    ok "$name"
}

json_ok() { # name file
    python3 - "$2" <<'PY' && ok "$1" || bad "$1 (invalid JSON)"
import json,sys
json.load(open(sys.argv[1]))
PY
}

# --- build ------------------------------------------------------------------
# Always rebuild from the current sources unless the caller hands us a binary,
# so the suite can never silently test a stale artifact.
if [ -z "$CLI_ARG" ]; then
    say "[*] building native CLI from source -> $CLI"
    mkdir -p "$ROOT/build"
    if command -v g++ >/dev/null 2>&1; then
        g++ -O2 -Wall -Wextra -o "$CLI" "$ROOT/tools/nrth_audit_cli.c" "$ROOT/nrth_audit.cpp" || exit 1
    else
        ZIG="${ZIG:-$(command -v zig || true)}"
        [ -n "$ZIG" ] || { say "[!] need g++ or zig"; exit 1; }
        "$ZIG" c++ -O2 -o "$CLI" "$ROOT/tools/nrth_audit_cli.c" "$ROOT/nrth_audit.cpp" || exit 1
    fi
elif [ ! -x "$CLI" ]; then
    say "[!] $CLI is not executable"; exit 1
fi

mkdir -p "$WORK"
say "[*] fixtures -> $WORK"
python3 "$ROOT/tools/make_test_image.py" "$WORK/clean.dll"    > /dev/null || exit 1
python3 "$ROOT/tools/make_test_image.py" "$WORK/suspect.dll" --kill 3 --kill 16 --detour 11 > /dev/null || exit 1
python3 "$ROOT/tools/make_test_image.py" "$WORK/nohidden.dll" --no-hidden > /dev/null || exit 1
head -c 200 /dev/urandom > "$WORK/not-a-pe.bin"

say ""
say "[1] module self-test"
check "self-test passes"                 0 "all checks passed" "$CLI" selftest
check "self-test writes a report file"   0 "report written"    "$CLI" selftest "$WORK/selftest.txt"
[ -s "$WORK/selftest.txt" ] && ok "report file is not empty" || bad "report file missing"

say ""
say "[2] PE view"
check "PE header/section map"            0 "\.text"            "$CLI" pe "$WORK/clean.dll"
check "rejects a non-PE file"            2 "-"                 "$CLI" pe "$WORK/not-a-pe.bin"

say ""
say "[3] audit (clean fixture)"
check "clean image -> exit 0"            0 "verdict: CLEAN"    "$CLI" audit "$WORK/clean.dll"
check "clean image: 20 intact"           0 "0 tampered, 20 intact" "$CLI" audit "$WORK/clean.dll"

say ""
say "[4] audit (suspect fixture: 2 x C3 kill, 1 x E9 detour)"
check "suspect image -> exit 1"          1 "verdict: SUSPECT"  "$CLI" audit "$WORK/suspect.dll"
check "C3 kill classified"               1 "KILL_RET"          "$CLI" audit "$WORK/suspect.dll"
check "E9 detour classified"             1 "DETOUR_JMP32"      "$CLI" audit "$WORK/suspect.dll"
check "3 tampered targets"               1 "3 tampered"        "$CLI" audit "$WORK/suspect.dll"

say ""
say "[5] differential audit"
check "diff clean vs suspect -> exit 1"  1 "SUSPECT"           "$CLI" diff "$WORK/clean.dll" "$WORK/suspect.dll"
check "diff reports new patch"           1 "NEW PATCH"         "$CLI" diff "$WORK/clean.dll" "$WORK/suspect.dll"
check "diff names target 11"             1 "^11 "             "$CLI" diff "$WORK/clean.dll" "$WORK/suspect.dll"
check "diff identical files -> exit 0"   0 "no new hook"       "$CLI" diff "$WORK/clean.dll" "$WORK/clean.dll"

say ""
say "[6] obfuscated signature recovery"
check "hidden records found -> exit 1"   1 "encoded record(s) recovered" "$CLI" hidden "$WORK/clean.dll"
check "key 0x2D recovered"               1 "key 0x2D"          "$CLI" hidden "$WORK/clean.dll"
check "key 0x20 recovered"               1 "key 0x20"          "$CLI" hidden "$WORK/clean.dll"
check "nothing hidden -> exit 0"         0 "no positional-XOR" "$CLI" hidden "$WORK/nohidden.dll"

say ""
say "[7] primitives"
check "prologue C3 -> kill, exit 1"      1 "KILL_RET"          "$CLI" prologue "C3 90 90 90"
check "prologue E9 -> detour, exit 1"    1 "DETOUR_JMP32"      "$CLI" prologue "E9 FB 04 00 00 8B"
check "prologue untouched -> exit 0"     0 "no"                "$CLI" prologue "55 8B EC 83 EC 10"
check "codec: client.dll key 0x2D"       0 "client.dll"        "$CLI" xor "b0 b8 bc b3 b9 ac f7 be b7 b0"
check "codec: netc.dll key 0x20"         0 "netc.dll"          "$CLI" xor "8e 84 96 80 ca 81 8a 8b"
check "pattern scan with wildcards"      0 "rva 0x001010"      "$CLI" scan "$WORK/clean.dll" "55 8B EC ? ? ? ? ? ? FF 75"
check "catalogue listing"                0 "client.dll"        "$CLI" sigs
check "version banner"                   0 "nrthaudit 1.2.0"   "$CLI" version
check "unknown command -> usage"         2 "-"                 "$CLI" definitely-not-a-command

say ""
say "[8] machine-readable output"
"$CLI" audit "$WORK/suspect.dll" --json > "$WORK/audit.json" 2>/dev/null
json_rc=$?
if [ "$json_rc" -eq 1 ]; then ok "audit --json runs and exits 1 on findings"
else bad "audit --json (exit $json_rc, expected 1)"; fi
json_ok "audit --json is valid JSON" "$WORK/audit.json"
"$CLI" diff "$WORK/clean.dll" "$WORK/suspect.dll" --json > "$WORK/diff.json" 2>/dev/null
json_ok "diff --json is valid JSON" "$WORK/diff.json"
"$CLI" hidden "$WORK/clean.dll" --json > "$WORK/hidden.json" 2>/dev/null
json_ok "hidden --json is valid JSON" "$WORK/hidden.json"

say ""
say "[9] batch triage + report files"
mkdir -p "$WORK/cleanonly"
cp "$WORK/clean.dll" "$WORK/nohidden.dll" "$WORK/cleanonly/"
check "batch on a mixed folder -> exit 1"  1 "SUSPECT"  "$CLI" batch "$WORK"
check "batch names the patched targets"    1 "3,11,16"  "$CLI" batch "$WORK"
check "batch counts modules"               1 "3 module(s)" "$CLI" batch "$WORK"
check "batch on clean folder -> exit 0"    0 "verdict: CLEAN" "$CLI" batch "$WORK/cleanonly"
check "batch rejects an empty folder"      2 "-"         "$CLI" batch "$WORK/does-not-exist"
"$CLI" batch "$WORK" --json > "$WORK/batch.json" 2>/dev/null
json_ok "batch --json is valid JSON" "$WORK/batch.json"
check "--out writes an audit report"       1 "-"         "$CLI" audit "$WORK/suspect.dll" --out "$WORK/report.txt"
[ -s "$WORK/report.txt" ] && grep -q "verdict: SUSPECT" "$WORK/report.txt" \
    && ok "--out report contains the verdict" || bad "--out report content"
check "--out: unwritable path -> exit 2"   2 "-"         "$CLI" audit "$WORK/clean.dll" --out /nonexistent-dir/x.txt

say ""
say "-------------------------------------------------------------"
say "tests: $((PASS + FAIL))   passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
