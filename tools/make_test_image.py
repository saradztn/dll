#!/usr/bin/env python3
"""
make_test_image.py — synthetic PE fixture generator for the NRTH audit module.

WHAT IT IS
    A *fixture* generator. It builds a tiny, valid PE32 image whose .text
    section contains nothing but the catalogue's published byte patterns laid
    out at known RVAs, optionally with selected functions "killed" (C3) or
    "detoured" (E9 rel32) — exactly the footprints the audit module classifies.
    .data optionally holds positional-XOR encoded copies of the same patterns,
    which is how the sample keeps its spaghetti strings at rest.

WHAT IT IS NOT
    It contains no code from the analysed module, no shellcode, no feature
    logic, nothing executable at all: the generated image is inert test data
    used to prove that `audit` / `diff` / `hidden` classify correctly.

usage:
    make_test_image.py out.dll [--kill ID]... [--detour ID]... [--no-hidden]
                               [--pattern-file nrth_auditsigs.h]
"""
import argparse
import os
import re
import struct
import sys

TOK_HEX = re.compile(r"^[0-9A-Fa-f]{2}$")


def load_patterns(path):
    """Parse g_NrthSigTable from nrth_auditsigs.h -> [(id, pattern), ...]"""
    src = open(path, encoding="utf-8", errors="replace").read()
    entries = re.findall(r"\{\s*(\d+)\s*,\s*\"([^\"]+)\"", src)
    if not entries:
        sys.exit(f"[!] no signatures found in {path}")
    return [(int(i), p) for i, p in entries]


def tokens(pattern):
    return pattern.split()


def bytes_of(tok):
    """A pattern token -> concrete byte (wildcards become 0x90)."""
    if tok in ("?", "??", "*"):
        return 0x90
    return int(tok, 16)


def head_replace(pattern, head, footprint):
    """Mirror of NrthPatPatchHead: replace the first `head` tokens with footprint."""
    t = tokens(pattern)
    return footprint + t[head:]


def build_text(patterns, kills, detours):
    """Lay the patterns out as pseudo-functions; returns (blob, {id: offset})."""
    blob = bytearray()
    offsets = {}
    for sid, pat in patterns:
        blob += b"\xCC" * 16
        offsets[sid] = len(blob)
        if sid in kills:
            toks = head_replace(pat, 1, ["C3"])
        elif sid in detours:
            toks = head_replace(pat, 5, ["E9", "FB", "04", "00", "00"])
        else:
            toks = tokens(pat)
        blob += bytes(bytes_of(t) for t in toks)
        blob += b"\xCC" * 16
    return bytes(blob), offsets


def encode_record(text, key):
    """out[p] = in[p] ^ ((p - key) & 0xFF)"""
    return bytes(((b ^ ((p - key) & 0xFF)) & 0xFF) for p, b in enumerate(text))


def terminator_run(n, key, start):
    """Bytes that decode to 0x00 at positions start..start+n-1 for `key`.

    The codec is positional, so a plain 0x00 filler does NOT decode to a NUL:
    the run must be (p - key) & 0xFF to terminate cleanly (this is exactly how
    the original module terminates its spaghetti strings).
    """
    return bytes(((start + i - key) & 0xFF) for i in range(n))


def build_data(patterns):
    blob = bytearray()
    blob += terminator_run(8, 0x2D, 0)
    for key, sid in ((0x2D, patterns[0][0]), (0x2D, patterns[1][0]), (0x20, patterns[2][0])):
        pat = next(p for i, p in patterns if i == sid)
        blob += encode_record(pat.encode("ascii"), key)
        blob += terminator_run(8, key, len(blob))
    return bytes(blob)


def build_pe(sections):
    """sections: [(name, blob)] -> raw PE32 bytes. .text first, 0x1000/0x200 aligned."""
    SEC_ALIGN, FILE_ALIGN, IMAGE_BASE = 0x1000, 0x200, 0x400000
    headers = 0x400
    headers += len(sections) * 40
    headers = (headers + FILE_ALIGN - 1) // FILE_ALIGN * FILE_ALIGN

    raw_off = headers
    sec_headers = []
    rva = SEC_ALIGN
    for name, blob in sections:
        vsize = (len(blob) + SEC_ALIGN - 1) // SEC_ALIGN * SEC_ALIGN or SEC_ALIGN
        rsize = (len(blob) + FILE_ALIGN - 1) // FILE_ALIGN * FILE_ALIGN or FILE_ALIGN
        chars = 0x60000020 if name == ".text" else 0xC0000040  # code|exec|read / init|read|write
        sec_headers.append((name, rva, vsize, raw_off, rsize, chars))
        rva += vsize
        raw_off += rsize

    size_of_image = rva

    out = bytearray(b"\x00" * headers)
    # --- DOS header / stub
    out[0:2] = b"MZ"
    struct.pack_into("<H", out, 0x3C, 0x40)
    out[0x40:0x44] = b"PE\x00\x00"
    # --- COFF header
    struct.pack_into("<HHIIIHH", out, 0x44, 0x014C, len(sections), 0x5F5E1000,
                     0, 0, 0x00E0, 0x0102)
    # --- optional header (PE32)
    opt = 0x44 + 20
    # PE32 optional header field offsets (relative to `opt`)
    OH_MAGIC, OH_ENTRY, OH_BASECODE, OH_BASEDATA = 0, 16, 20, 24
    OH_IMAGEBASE, OH_SECALIGN, OH_FILEALIGN = 28, 32, 36
    OH_OSVER, OH_IMGVER, OH_SUBVER = 40, 44, 48
    OH_WIN32VER, OH_SIZEOFIMAGE, OH_SIZEOFHEADERS, OH_CHECKSUM = 52, 56, 60, 64
    OH_SUBSYSTEM, OH_DLLCHARS = 68, 70
    OH_STACKRES, OH_STACKCOM, OH_HEAPRES, OH_HEAPCOM = 72, 76, 80, 84
    OH_LOADERFLAGS, OH_NUMRVA = 88, 92

    struct.pack_into("<H", out, opt + OH_MAGIC, 0x10B)
    out[opt + 2] = 9
    struct.pack_into("<II", out, opt + 4, sum(len(b) for _, b in sections), 0)
    struct.pack_into("<I", out, opt + OH_ENTRY, 0x1000)          # entry point RVA
    struct.pack_into("<II", out, opt + OH_BASECODE, 0x1000, 0x2000)
    struct.pack_into("<I", out, opt + OH_IMAGEBASE, IMAGE_BASE)
    struct.pack_into("<II", out, opt + OH_SECALIGN, SEC_ALIGN, FILE_ALIGN)
    struct.pack_into("<HH", out, opt + OH_OSVER, 6, 0)
    struct.pack_into("<HH", out, opt + OH_IMGVER, 0, 0)
    struct.pack_into("<HH", out, opt + OH_SUBVER, 6, 0)
    struct.pack_into("<I", out, opt + OH_WIN32VER, 0)
    struct.pack_into("<I", out, opt + OH_SIZEOFIMAGE, size_of_image)
    struct.pack_into("<I", out, opt + OH_SIZEOFHEADERS, headers)
    struct.pack_into("<I", out, opt + OH_CHECKSUM, 0)
    struct.pack_into("<H", out, opt + OH_SUBSYSTEM, 2)            # WINDOWS_GUI
    struct.pack_into("<H", out, opt + OH_DLLCHARS, 0x0140)
    struct.pack_into("<IIII", out, opt + OH_STACKRES, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", out, opt + OH_LOADERFLAGS, 0)
    struct.pack_into("<I", out, opt + OH_NUMRVA, 16)
    # --- section headers
    sec_tab = 0x44 + 20 + 0xE0
    for i, (name, srva, vsize, raw, rsize, chars) in enumerate(sec_headers):
        e = sec_tab + i * 40
        out[e:e + 8] = name.encode().ljust(8, b"\x00")
        struct.pack_into("<IIII", out, e + 8, vsize, srva, rsize, raw)
        struct.pack_into("<I", out, e + 36, chars)
    # --- section bodies
    for (_, _, _, raw, rsize, _), (_, blob) in zip(sec_headers, sections):
        out[raw:raw + len(blob)] = blob
        out[raw + len(blob):raw + rsize] = b"\x00" * (rsize - len(blob))
    return bytes(out)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="synthetic PE fixture for NRTH_audit")
    ap.add_argument("out")
    ap.add_argument("--kill", action="append", type=int, default=[], help="id: overwrite byte 0 with C3")
    ap.add_argument("--detour", action="append", type=int, default=[], help="id: overwrite 5 bytes with E9 rel32")
    ap.add_argument("--no-hidden", action="store_true", help="omit the encoded strings in .data")
    ap.add_argument("--pattern-file", default=os.path.join(here, os.pardir, "nrth_auditsigs.h"))
    args = ap.parse_args()

    patterns = load_patterns(args.pattern_file)
    text, offs = build_text(patterns, set(args.kill), set(args.detour))
    sections = [(".text", text)]
    if not args.no_hidden:
        sections.append((".data", build_data(patterns)))
    img = build_pe(sections)

    with open(args.out, "wb") as f:
        f.write(img)

    print(f"[*] wrote {args.out}: {len(img)} bytes, {len(patterns)} signatures, "
          f".text {len(text)} bytes, kills={sorted(set(args.kill))}, detours={sorted(set(args.detour))}")
    for sid, off in offs.items():
        tag = "KILL" if sid in args.kill else "DETOUR" if sid in args.detour else "pristine"
        print(f"    sig {sid:>2}  .text+0x{off:04X}  rva 0x1000+0x{off:04X}  {tag}")


if __name__ == "__main__":
    main()
