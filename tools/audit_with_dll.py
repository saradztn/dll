#!/usr/bin/env python3
"""
audit_with_dll.py — drive the built NRTH_audit DLL from Python via ctypes.

Read-only: it calls the module's exported audit functions on ONE image file the
operator already has, and prints the result. Nothing is injected, hooked or
written anywhere.

usage:
    python audit_with_dll.py selftest
    python audit_with_dll.py sigs
    python audit_with_dll.py audit  <image>
    python audit_with_dll.py diff   <clean> <suspect>
    python audit_with_dll.py --dll dist/NRTH_audit.dll audit <image>

library lookup order (first hit wins):
    --dll PATH, $NRTH_AUDIT_DLL, dist/NRTH_audit.dll, dist/NRTH_audit_x64.dll,
    dist/linux/NRTH_audit.so, ./NRTH_audit.dll
"""
import argparse
import ctypes
import os
import sys

MAX_SIG = 64  # generous upper bound; the real catalogue count comes from NrthSigCount()

AUDIT_STATE = {
    0: "UNKNOWN", 1: "PRISTINE", 2: "DETOUR_JMP32", 3: "DETOUR_FARJMP",
    4: "DETOUR_PUSHRET", 5: "KILL_RET", 6: "KILL_RETN", 7: "STUB_IMM",
    8: "PAD", 9: "JMP_INDIRECT",
}
TAMPER_STATES = {2, 3, 4, 5, 6, 7, 9}


class NrthSignature(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint32),
        ("pattern", ctypes.c_char_p),
        ("target", ctypes.c_char_p),
        ("role", ctypes.c_char_p),
        ("decryptor_va", ctypes.c_uint32),
        ("pattern_len", ctypes.c_uint32),
        ("xor_key", ctypes.c_uint32),
        ("confidence", ctypes.c_uint32),
        ("evidence", ctypes.c_char_p),
    ]


class NrthSigFinding(ctypes.Structure):
    _fields_ = [
        ("sigId", ctypes.c_uint32),
        ("fullHits", ctypes.c_uint32),
        ("patchedHits", ctypes.c_uint32),
        ("firstFullRva", ctypes.c_uint32),
        ("firstPatchedRva", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
        ("detail", ctypes.c_uint32),
        ("textSectionOnly", ctypes.c_uint32),
    ]


class NrthAuditDiffRow(ctypes.Structure):
    _fields_ = [
        ("sigId", ctypes.c_uint32),
        ("cleanFull", ctypes.c_uint32),
        ("cleanPatched", ctypes.c_uint32),
        ("susFull", ctypes.c_uint32),
        ("susPatched", ctypes.c_uint32),
        ("susState", ctypes.c_uint32),
        ("susRva", ctypes.c_uint32),
        ("susDetail", ctypes.c_uint32),
        ("addedFootprint", ctypes.c_uint32),
        ("targetLost", ctypes.c_uint32),
        ("susUnlocated", ctypes.c_uint32),
    ]


def library_candidates(explicit):
    """Ordered candidate list - platform-appropriate names first."""
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    dist = os.path.join(root, "dist")
    win = [os.path.join(dist, "NRTH_audit.dll"),
           os.path.join(dist, "NRTH_audit_x64.dll"),
           os.path.join(root, "NRTH_audit.dll")]
    posix = [os.path.join(dist, "linux", "NRTH_audit.so"),
             os.path.join(dist, "NRTH_audit.so")]
    order = win + posix if os.name == "nt" else posix + win
    cands = [explicit, os.environ.get("NRTH_AUDIT_DLL")] + order
    return [c for c in cands if c]


def bind(explicit):
    """Load the first candidate that actually dlopen()s on this platform."""
    tried = []
    for path in library_candidates(explicit):
        if not os.path.exists(path):
            continue
        tried.append(path)
        if os.name == "nt" and hasattr(os, "add_dll_directory"):
            try:
                os.add_dll_directory(os.path.dirname(os.path.abspath(path)) or ".")
            except OSError:
                pass
        try:
            lib = ctypes.CDLL(path)
        except OSError:
            continue  # e.g. a Windows .dll on Linux - try the next candidate
        _declare(lib)
        return lib, path
    sys.exit("[!] no loadable NRTH_audit library found - build it first (./build.sh) "
             "or pass --dll PATH\n    tried: " + (", ".join(tried) if tried else "<none present>"))


def _declare(lib):
    lib.NrthAuditVersion.restype = ctypes.c_char_p
    lib.NrthAuditVersion.argtypes = []
    lib.NrthSigCount.restype = ctypes.c_uint32
    lib.NrthSigAt.restype = ctypes.POINTER(NrthSignature)
    lib.NrthSigAt.argtypes = [ctypes.c_uint32]
    lib.NrthPrologueStateName.restype = ctypes.c_char_p
    lib.NrthPrologueStateName.argtypes = [ctypes.c_uint32]
    lib.NrthAuditImageFile.restype = ctypes.c_int32
    lib.NrthAuditImageFile.argtypes = [ctypes.c_char_p, ctypes.POINTER(NrthSigFinding), ctypes.c_uint32]
    lib.NrthAuditDiffFiles.restype = ctypes.c_int32
    lib.NrthAuditDiffFiles.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                       ctypes.POINTER(NrthAuditDiffRow), ctypes.c_uint32]
    lib.NrthAuditSelfTest.restype = ctypes.c_int32
    lib.NrthAuditSelfTest.argtypes = [ctypes.c_char_p, ctypes.c_uint32]


def cmd_selftest(lib):
    buf = ctypes.create_string_buffer(8192)
    failed = lib.NrthAuditSelfTest(buf, len(buf))
    print(buf.value.decode("utf-8", "replace"), end="")
    return 3 if failed else 0


def cmd_sigs(lib):
    n = lib.NrthSigCount()
    print(f"catalogue: {n} entries from {lib.NrthAuditVersion().decode()}")
    for i in range(1, n + 1):
        s = lib.NrthSigAt(i).contents
        print(f"  {s.id:>2}  {s.target.decode():<10} conf={s.confidence}  {s.role.decode()}")
    return 0


def cmd_audit(lib, image):
    n = lib.NrthSigCount()
    arr = (NrthSigFinding * max(n, 1))()
    rc = lib.NrthAuditImageFile(image.encode(), arr, n)
    if rc < 0:
        print(f"[!] audit failed on {image} (status {rc})", file=sys.stderr)
        return 2
    print(f"audit: {image}  ({lib.NrthAuditVersion().decode()})")
    tampered = 0
    for i in range(n):
        f = arr[i]
        if not (f.sigId or f.fullHits or f.patchedHits):
            continue
        st = AUDIT_STATE.get(f.state, "?")
        verdict = "TAMPERED" if f.patchedHits else ("INTACT" if f.fullHits else "NOT_LOCATED")
        if f.patchedHits:
            tampered += 1
        rva = f.firstPatchedRva or f.firstFullRva
        print(f"  #{f.sigId:<3} {verdict:<11} {st:<14} full={f.fullHits} patched={f.patchedHits} rva=0x{rva:06X}")
    print(f"-> {tampered} target(s) with a detour/kill prologue")
    return 1 if tampered else 0


def cmd_diff(lib, clean, suspect):
    n = lib.NrthSigCount()
    rows = (NrthAuditDiffRow * max(n, 1))()
    rc = lib.NrthAuditDiffFiles(clean.encode(), suspect.encode(), rows, n)
    if rc < 0:
        print("[!] diff failed - are both paths readable PE images?", file=sys.stderr)
        return 2
    print(f"diff: {clean}  vs  {suspect}")
    for i in range(n):
        d = rows[i]
        if not (d.addedFootprint or d.susUnlocated or d.targetLost):
            continue
        why = ("NEW PATCH" if d.addedFootprint else
               "target relocated" if d.susUnlocated else "target missing")
        print(f"  #{d.sigId:<3} {why:<17} {AUDIT_STATE.get(d.susState, '?')} @ rva 0x{d.susRva:06X}")
    print(f"-> {rc} function(s) newly patched in the suspect image")
    return 1 if rc else 0


def main():
    ap = argparse.ArgumentParser(description="ctypes front-end for NRTH_audit.dll")
    ap.add_argument("--dll", help="path to NRTH_audit.dll / .so")
    ap.add_argument("-q", "--quiet", action="store_true", help="do not print which library was loaded")
    ap.add_argument("command", choices=["selftest", "sigs", "audit", "diff"])
    ap.add_argument("args", nargs="*")
    a = ap.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    lib, loaded = bind(a.dll)
    if not a.quiet:
        print(f"[*] loaded {loaded}")
    if a.command == "selftest":
        return cmd_selftest(lib)
    if a.command == "sigs":
        return cmd_sigs(lib)
    if a.command == "audit":
        if not a.args:
            sys.exit("usage: audit <image>")
        return cmd_audit(lib, a.args[0])
    if a.command == "diff":
        if len(a.args) < 2:
            sys.exit("usage: diff <clean> <suspect>")
        return cmd_diff(lib, a.args[0], a.args[1])
    return 2


if __name__ == "__main__":
    sys.exit(main())
