/**
 * ============================================================================
 * nrth_audit_cli.c - NRTH/NVX defensive audit - console front-end (EXE)
 * ============================================================================
 * Read-only analysis harness around NRTH_audit.dll / nrth_audit.cpp.
 *
 * WHAT THIS PROGRAM DOES:
 *   - opens ONE file the operator names on the command line (a module copy or a
 *     memory dump the operator already owns) and reads it into private memory;
 *   - reports where the catalogue's hook targets sit, whether their prologues
 *     look patched, whether obfuscated signature strings are embedded;
 *   - prints findings as text or JSON on stdout (optionally to a report file).
 *
 * WHAT THIS PROGRAM DELIBERATELY DOES NOT DO:
 *   - never opens another process, never injects, never hooks, never patches,
 *     never changes memory protection, never writes outside its own buffers;
 *   - contains no script payload, no overlay, no loader, no game feature logic
 *     and no evasion logic;
 *   - performs no network access and never modifies, deletes or renames the
 *     file it is asked to analyse (files are opened read-only, "rb").
 *
 * Build: see build.sh (Linux/macOS via zig or gcc) and build_msvc.bat /
 *        build_mingw.bat (native Windows).
 * ============================================================================
 */
#include "../nrth_audit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLI_VERSION "1.2.0"

#define CLI_EXIT_OK       0
#define CLI_EXIT_FINDINGS 1
#define CLI_EXIT_USAGE    2
#define CLI_EXIT_SELFTEST 3

#define CLI_MAX_IMAGE (64u * 1024u * 1024u)

/* ------------------------------------------------------------------------- */
/* small helpers                                                             */
/* ------------------------------------------------------------------------- */
static const char *cli_base(const char *p)
{
    const char *b = p;
    for (const char *s = p; *s; ++s) {
        if (*s == '\\' || *s == '/') b = s + 1;
    }
    return b;
}

static uint8_t *cli_load(const char *path, uint32_t *outSize)
{
    FILE *f = fopen(path, "rb");
    long  sz;
    uint8_t *buf;

    if (!f) {
        fprintf(stderr, "[!] cannot open '%s' for reading (read-only access failed)\n", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); fprintf(stderr, "[!] seek failed on '%s'\n", path); return NULL; }
    sz = ftell(f);
    if (sz <= 0) { fclose(f); fprintf(stderr, "[!] '%s' is empty or unseekable\n", path); return NULL; }
    if ((unsigned long)sz > CLI_MAX_IMAGE) {
        fclose(f);
        fprintf(stderr, "[!] '%s' is %ld bytes; module images above %u bytes are out of scope\n",
                path, sz, (unsigned)CLI_MAX_IMAGE);
        return NULL;
    }
    rewind(f);
    buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); fprintf(stderr, "[!] out of memory for %ld bytes\n", sz); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f);
        fprintf(stderr, "[!] short read on '%s'\n", path);
        return NULL;
    }
    fclose(f);
    *outSize = (uint32_t)sz;
    return buf;
}

static void cli_free(void *p) { free(p); }

/* parse "55 8b ??" / "558BEC" style hex into bytes; returns count or -1 */
static int32_t cli_parse_hex(const char *s, uint8_t *out, uint32_t cap)
{
    uint32_t n = 0;
    int hi = -1;
    if (!s) return -1;
    for (; *s; ++s) {
        int v;
        if (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n' || *s == ',' || *s == '-') continue;
        v = (*s >= '0' && *s <= '9') ? *s - '0'
          : (*s >= 'a' && *s <= 'f') ? *s - 'a' + 10
          : (*s >= 'A' && *s <= 'F') ? *s - 'A' + 10
          : -1;
        if (v < 0) return -1;
        if (hi < 0) { hi = v; continue; }
        if (n >= cap) return -1;
        out[n++] = (uint8_t)((hi << 4) | v);
        hi = -1;
    }
    if (hi >= 0) return -1; /* dangling nibble */
    return (int32_t)n;
}

static void cli_json_str(const char *s)
{
    putchar('"');
    for (; s && *s; ++s) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout);  break;
        case '\r': fputs("\\r", stdout);  break;
        case '\t': fputs("\\t", stdout);  break;
        default:
            if (c < 0x20) printf("\\u%04x", c);
            else putchar((int)c);
        }
    }
    putchar('"');
}

static const char *cli_verdict(uint32_t fullHits, uint32_t patchedHits)
{
    if (patchedHits) return "TAMPERED";
    if (fullHits)    return "INTACT";
    return "NOT_LOCATED";
}

static const char *cli_state_name(uint32_t state)
{
    const char *n = NrthPrologueStateName(state);
    return n ? n : "UNKNOWN";
}

/* shorten "PRISTINE (pattern matches byte-for-byte)" -> "PRISTINE" */
static void cli_state_short(uint32_t state, char *out, size_t cap)
{
    const char *n = cli_state_name(state);
    size_t i = 0;
    while (n[i] && n[i] != ' ' && n[i] != '(' && i + 1 < cap) { out[i] = n[i]; ++i; }
    out[i] = '\0';
}

/* ------------------------------------------------------------------------- */
/* commands                                                                  */
/* ------------------------------------------------------------------------- */
static void cli_usage(FILE *fp)
{
    fputs(
        "nrth-audit " CLI_VERSION " - read-only tamper audit for the NRTH/NVX hook targets\n"
        "\n"
        "usage: nrth_audit_cli <command> [arguments]\n"
        "\n"
        "  version                             module + front-end version string\n"
        "  selftest [report.txt]               run the module's built-in self-test\n"
        "  sigs                                list the signature catalogue\n"
        "  pe <image>                          print the PE header / section map\n"
        "  audit <image> [--json]              locate every catalogue target and\n"
        "                                      classify each prologue (main command)\n"
        "  diff <clean> <suspect> [--json] [--all]\n"
        "                                      compare a trusted copy against a\n"
        "                                      suspect one; alert on new patching\n"
        "                                      (--all also lists unchanged targets)\n"
        "  hidden <image> [minLen] [--json]    recover XOR-obfuscated signature\n"
        "                                      strings embedded in .data/.rdata\n"
        "  scan <image> <pattern> [pattern..]  raw byte-pattern search (wildcards\n"
        "                                      '?' and doubled-'?' tokens supported)\n"
        "  prologue <hexbytes>                 classify one prologue byte sequence\n"
        "  xor <hexbytes>                      crack a positional-XOR record\n"
        "\n"
        "exit codes: 0 clean  1 findings  2 usage/IO error  3 self-test failure\n"
        "notes:      <image> = a module copy or memory dump you already own.\n"
        "            Nothing is ever written to the analysed file.\n",
        fp);
}

static int cli_cmd_version(void)
{
    printf("nrth_audit_cli %s\n%s\ncatalogue entries: %u\n",
           CLI_VERSION, NrthAuditVersion(), (unsigned)NrthSigCount());
    return CLI_EXIT_OK;
}

static int cli_cmd_selftest(int argc, char **argv)
{
    char report[8192];
    int32_t failed;
    const char *outPath = (argc > 0 && argv[0][0] != '-') ? argv[0] : NULL;

    report[0] = '\0';
    failed = NrthAuditSelfTest(report, (uint32_t)sizeof(report));
    fputs(report, stdout);

    if (outPath) {
        FILE *f = fopen(outPath, "wb");
        if (!f) {
            fprintf(stderr, "[!] cannot write report '%s'\n", outPath);
            return CLI_EXIT_USAGE;
        }
        fputs(report, f);
        fclose(f);
        printf("[*] report written to %s\n", outPath);
    }
    return failed ? CLI_EXIT_SELFTEST : CLI_EXIT_OK;
}

static int cli_cmd_sigs(void)
{
    uint32_t i, n = NrthSigCount();
    printf("signature catalogue (%u entries)\n", (unsigned)n);
    printf("%-4s %-9s %-52s %-8s %s\n", "id", "module", "role", "conf", "evidence");
    for (i = 1; i <= n; ++i) {
        const NrthSignature *s = NrthSigAt(i);
        if (!s) continue;
        printf("%-4u %-9s %-52s %-8u %s\n",
               (unsigned)s->id,
               s->target ? s->target : "?",
               s->role ? s->role : "?",
               (unsigned)s->confidence,
               s->evidence ? s->evidence : "?");
    }
    printf("\npattern bytes per entry: %u   xor keys in use: 0x2D (client), 0x20 (netc)\n",
           (unsigned)(n ? NrthSigAt(1)->pattern_len : 0));
    return CLI_EXIT_OK;
}

static int cli_cmd_pe(const char *path)
{
    uint32_t size = 0, i;
    uint8_t *buf = cli_load(path, &size);
    NrthPeView pe;
    int32_t r;

    if (!buf) return CLI_EXIT_USAGE;
    r = NrthPeMap(buf, size, &pe);
    if (r != NVXA_OK) {
        fprintf(stderr, "[!] '%s' is not a parseable PE image (status %d)\n", path, (int)r);
        cli_free(buf);
        return CLI_EXIT_USAGE;
    }
    printf("file            : %s (%u bytes)\n", cli_base(path), (unsigned)size);
    printf("machine         : 0x%04X%s\n", (unsigned)pe.machine,
           pe.machine == 0x014C ? " (i386 / PE32)" : pe.machine == 0x8664 ? " (AMD64 / PE32+)" : "");
    printf("image base      : 0x%08X\n", (unsigned)pe.imageBase);
    printf("entry RVA       : 0x%08X\n", (unsigned)pe.entryRva);
    printf(".text RVA       : 0x%08X\n", (unsigned)NrthPeTextRva(&pe));
    printf("timestamp       : 0x%08X\n", (unsigned)pe.timestamp);
    printf("characteristics : 0x%04X%s\n", (unsigned)pe.characteristics,
           (pe.characteristics & 0x2000) ? " (DLL)" : "");
    printf("image layout    : %s\n", pe.mapped ? "memory-mapped (RVA == file offset)"
                                              : "raw on-disk layout");
    printf("sections        : %u\n", (unsigned)pe.nSections);
    printf("\n%-10s %-10s %-10s %-10s %-10s %s\n", "name", "rva", "vsize", "raw", "rsize", "flags");
    for (i = 0; i < pe.nSections; ++i) {
        const NrthPeSection *s = &pe.sec[i];
        char flags[16];
        snprintf(flags, sizeof(flags), "%c%c%c",
                 (s->characteristics & 0x20000000) ? 'x' : '-',
                 (s->characteristics & 0x40000000) ? 'r' : '-',
                 (s->characteristics & 0x80000000) ? 'w' : '-');
        printf("%-10s 0x%08X 0x%08X 0x%08X 0x%08X %s\n",
               s->name, (unsigned)s->rva, (unsigned)s->vsize,
               (unsigned)s->raw, (unsigned)s->rsize, flags);
    }
    cli_free(buf);
    return CLI_EXIT_OK;
}

static int cli_cmd_audit(const char *path, int json)
{
    uint32_t size = 0, i, n = NrthSigCount();
    uint8_t *buf = cli_load(path, &size);
    NrthSigFinding *f;
    int32_t r, tampered = 0, intact = 0, missing = 0, first = 1;

    if (!buf) return CLI_EXIT_USAGE;
    f = (NrthSigFinding *)calloc(n ? n : 1, sizeof(NrthSigFinding));
    if (!f) { cli_free(buf); fprintf(stderr, "[!] out of memory\n"); return CLI_EXIT_USAGE; }

    r = NrthAuditImage(buf, size, f, n);
    if (r < 0) {
        fprintf(stderr, "[!] audit failed on '%s' (status %d%s)\n", path, (int)r,
                (r == NVXA_E_FORMAT || r == NVXA_E_INVALID) ? " - not a PE image, or too small" : "");
        free(f); cli_free(buf);
        return CLI_EXIT_USAGE;
    }

    for (i = 0; i < n; ++i) {
        if (f[i].patchedHits) ++tampered;
        else if (f[i].fullHits) ++intact;
        else ++missing;
    }

    if (json) {
        printf("{\n  \"tool\": \"nrth_audit_cli\",\n  \"moduleVersion\": ");
        cli_json_str(NrthAuditVersion());
        printf(",\n  \"file\": ");
        cli_json_str(path);
        printf(",\n  \"size\": %u,\n  \"catalogueEntries\": %u,\n",
               (unsigned)size, (unsigned)n);
        printf("  \"summary\": { \"tampered\": %d, \"intact\": %d, \"notLocated\": %d },\n",
               (int)tampered, (int)intact, (int)missing);
        printf("  \"findings\": [\n");
        for (i = 0; i < n; ++i) {
            const NrthSignature *s;
            char st[48];
            if (!f[i].sigId && !f[i].fullHits && !f[i].patchedHits) continue;
            s = NrthSigAt(f[i].sigId ? f[i].sigId : i + 1);
            cli_state_short(f[i].state, st, sizeof(st));
            printf("    %s{ \"id\": %u, \"target\": ",
                   first ? "" : ",\n", (unsigned)(f[i].sigId ? f[i].sigId : i + 1));
            cli_json_str(s && s->target ? s->target : "?");
            printf(", \"role\": ");
            cli_json_str(s && s->role ? s->role : "?");
            printf(", \"confidence\": %u, \"verdict\": ", (unsigned)(s ? s->confidence : 0));
            cli_json_str(cli_verdict(f[i].fullHits, f[i].patchedHits));
            printf(", \"state\": ");
            cli_json_str(st);
            printf(", \"tamper\": %s, \"fullHits\": %u, \"patchedHits\": %u,"
                   " \"firstFullRva\": %u, \"firstPatchedRva\": %u, \"detail\": %u }",
                   NrthPrologueIsTamper(f[i].state) ? "true" : "false",
                   (unsigned)f[i].fullHits, (unsigned)f[i].patchedHits,
                   (unsigned)f[i].firstFullRva, (unsigned)f[i].firstPatchedRva,
                   (unsigned)f[i].detail);
            first = 0;
        }
        printf("\n  ]\n}\n");
    } else {
        printf("NRTH/NVX tamper audit - %s (%u bytes)\n", cli_base(path), (unsigned)size);
        printf("%s\n", NrthAuditVersion());
        printf("\n%-4s %-13s %-13s %-8s %-8s %-10s %s\n",
               "id", "verdict", "prologue", "full", "patched", "rva", "target");
        for (i = 0; i < n; ++i) {
            const NrthSignature *s;
            char st[48];
            if (!f[i].sigId && !f[i].fullHits && !f[i].patchedHits) continue;
            s = NrthSigAt(f[i].sigId ? f[i].sigId : i + 1);
            cli_state_short(f[i].state, st, sizeof(st));
            printf("%-4u %-13s %-13s %-8u %-8u 0x%06X %s\n",
                   (unsigned)(f[i].sigId ? f[i].sigId : i + 1),
                   cli_verdict(f[i].fullHits, f[i].patchedHits),
                   st,
                   (unsigned)f[i].fullHits, (unsigned)f[i].patchedHits,
                   (unsigned)(f[i].firstPatchedRva ? f[i].firstPatchedRva : f[i].firstFullRva),
                   s && s->target ? s->target : "?");
            if (f[i].patchedHits) {
                printf("        - %s\n        - role: %s\n        - evidence: %s\n",
                       cli_state_name(f[i].state),
                       s && s->role ? s->role : "?",
                       s && s->evidence ? s->evidence : "?");
            }
        }
        printf("\nsummary: %u catalogue entries -> %d tampered, %d intact, %d not located\n",
               (unsigned)n, (int)tampered, (int)intact, (int)missing);
        if (tampered)
            printf("verdict: SUSPECT - %d hook target(s) carry a detour/kill prologue\n", (int)tampered);
        else if (intact)
            printf("verdict: CLEAN - every located target matches its reference pattern\n");
        else
            printf("verdict: INCONCLUSIVE - none of the catalogue targets were located;"
                   " this is probably not the module the catalogue describes\n");
    }
    free(f);
    cli_free(buf);
    return (tampered > 0) ? CLI_EXIT_FINDINGS : CLI_EXIT_OK;
}

static int cli_cmd_diff(const char *cleanPath, const char *susPath, int json, int showAll)
{
    uint32_t i, n = NrthSigCount();
    NrthAuditDiffRow *rows = (NrthAuditDiffRow *)calloc(n ? n : 1, sizeof(NrthAuditDiffRow));
    int32_t r, first = 1, flagged = 0;

    if (!rows) { fprintf(stderr, "[!] out of memory\n"); return CLI_EXIT_USAGE; }
    r = NrthAuditDiffFiles(cleanPath, susPath, rows, n);
    if (r < 0) {
        fprintf(stderr, "[!] diff failed (status %d) - check both paths are readable PE images\n", (int)r);
        free(rows);
        return CLI_EXIT_USAGE;
    }

    if (!json) {
        printf("differential audit\n  trusted : %s\n  suspect : %s\n\n", cli_base(cleanPath), cli_base(susPath));
        printf("%-4s %-24s %-24s %s\n", "id", "trusted (full/patched)", "suspect (full/patched)", "observation");
    } else {
        printf("{\n  \"tool\": \"nrth_audit_cli\",\n  \"moduleVersion\": ");
        cli_json_str(NrthAuditVersion());
        printf(",\n  \"command\": \"diff\",\n  \"trusted\": ");
        cli_json_str(cleanPath);
        printf(",\n  \"suspect\": ");
        cli_json_str(susPath);
        printf(",\n  \"rows\": [\n");
    }

    for (i = 0; i < n; ++i) {
        const NrthAuditDiffRow *d = &rows[i];
        const NrthSignature *s = NrthSigAt(d->sigId ? d->sigId : i + 1);
        char st[48];
        const char *obs = d->addedFootprint ? "NEW PATCH on a trusted function"
                        : d->susUnlocated   ? "target relocated/replaced (signature lost)"
                        : d->targetLost     ? "target missing in suspect image"
                        : (d->susPatched ? "already patched in both images" : "unchanged");
        cli_state_short(d->susState, st, sizeof(st));
        if (d->addedFootprint || d->susUnlocated || d->targetLost) ++flagged;
        if (!showAll && !d->addedFootprint && !d->susUnlocated && !d->targetLost &&
            d->cleanFull == d->susFull && d->cleanPatched == d->susPatched) continue;

        if (json) {
            printf("    %s{ \"id\": %u, \"target\": ", first ? "" : ",\n", (unsigned)d->sigId);
            cli_json_str(s && s->target ? s->target : "?");
            printf(", \"trustedFull\": %u, \"trustedPatched\": %u, \"suspectFull\": %u,"
                   " \"suspectPatched\": %u, \"suspectState\": ",
                   (unsigned)d->cleanFull, (unsigned)d->cleanPatched,
                   (unsigned)d->susFull, (unsigned)d->susPatched);
            cli_json_str(st);
            printf(", \"suspectRva\": %u, \"detail\": %u, \"addedFootprint\": %s,"
                   " \"targetLost\": %s, \"suspectUnlocated\": %s, \"observation\": ",
                   (unsigned)d->susRva, (unsigned)d->susDetail,
                   d->addedFootprint ? "true" : "false",
                   d->targetLost ? "true" : "false",
                   d->susUnlocated ? "true" : "false");
            cli_json_str(obs);
            printf(" }");
        } else {
            char a[24], b[24];
            snprintf(a, sizeof(a), "%u/%u", (unsigned)d->cleanFull, (unsigned)d->cleanPatched);
            snprintf(b, sizeof(b), "%u/%u", (unsigned)d->susFull, (unsigned)d->susPatched);
            printf("%-4u %-24s %-24s %s\n", (unsigned)d->sigId, a, b, obs);
            if (d->addedFootprint) {
                printf("        - %s @ rva 0x%06X (detail %u)\n",
                       cli_state_name(d->susState), (unsigned)d->susRva, (unsigned)d->susDetail);
            }
        }
        first = 0;
    }

    if (json) {
        if (!first) printf("\n");
        printf("  ],\n  \"flagged\": %d,\n  \"newlyPatched\": %d,\n  \"verdict\": ",
               (int)flagged, (int)r);
        cli_json_str(r > 0 ? "SUSPECT" : "CLEAN");
        printf("\n}\n");
    } else {
        printf("\n");
        if (r > 0)
            printf("verdict: SUSPECT - %d function(s) newly carry a hook/kill prologue in the suspect image\n", (int)r);
        else
            printf("verdict: no new hook/kill footprint found in the suspect image\n");
    }
    free(rows);
    return (r > 0) ? CLI_EXIT_FINDINGS : CLI_EXIT_OK;
}

static int cli_cmd_hidden(const char *path, uint32_t minLen, int json)
{
    uint32_t size = 0, i;
    uint8_t *buf = cli_load(path, &size);
    char *text;
    uint32_t *vas;
    int32_t found, flagged = 0;

    if (!buf) return CLI_EXIT_USAGE;
    text = (char *)calloc(1, 1u << 17);
    vas = (uint32_t *)calloc(512, sizeof(uint32_t));
    if (!text || !vas) {
        free(text); free(vas); cli_free(buf);
        fprintf(stderr, "[!] out of memory\n");
        return CLI_EXIT_USAGE;
    }

    found = NrthFindHiddenSignatures(buf, size, minLen, text, 1u << 17, vas, 512);
    if (found < 0) {
        fprintf(stderr, "[!] scan failed (status %d)\n", (int)found);
        free(text); free(vas); cli_free(buf);
        return CLI_EXIT_USAGE;
    }
    flagged = (found > 0) ? 1 : 0;

    if (json) {
        printf("{\n  \"tool\": \"nrth_audit_cli\",\n  \"command\": \"hidden\",\n  \"file\": ");
        cli_json_str(path);
        printf(",\n  \"minLen\": %u,\n  \"count\": %d,\n  \"records\": [\n",
               (unsigned)(minLen < 12 ? 12 : minLen), (int)found);
        for (i = 0; i < (uint32_t)found && i < 512; ++i)
            printf("    %s{ \"rva\": %u }", i ? ",\n" : "", (unsigned)vas[i]);
        printf("\n  ]\n}\n");
    } else {
        printf("obfuscated-signature scan - %s (min length %u)\n",
               cli_base(path), (unsigned)(minLen < 12 ? 12 : minLen));
        if (found <= 0) {
            printf("no positional-XOR encoded signature strings found\n");
        } else {
            fputs(text, stdout);
            printf("\n%u encoded record(s) recovered; first VA entries: ", (unsigned)found);
            for (i = 0; i < (uint32_t)found && i < 8; ++i) printf("0x%06X ", (unsigned)vas[i]);
            printf("\n");
        }
    }
    free(text); free(vas); cli_free(buf);
    return flagged ? CLI_EXIT_FINDINGS : CLI_EXIT_OK;
}

static int cli_cmd_scan(const char *path, int nPat, char **pats)
{
    uint32_t size = 0;
    uint8_t *buf = cli_load(path, &size);
    NrthPeView pe;
    int havePe, p;

    if (!buf) return CLI_EXIT_USAGE;
    havePe = (NrthPeMap(buf, size, &pe) == NVXA_OK);

    for (p = 0; p < nPat; ++p) {
        uint32_t hits[64];
        int32_t h = NrthPatScan(buf, size, pats[p], hits, 64);
        int32_t i;
        if (h < 0) {
            fprintf(stderr, "[!] pattern %d is malformed: %s\n", p + 1, pats[p]);
            cli_free(buf);
            return CLI_EXIT_USAGE;
        }
        printf("pattern[%d] %s -> %d hit(s)\n", p + 1, pats[p], (int)h);
        for (i = 0; i < h && i < 64; ++i) {
            printf("   file offset 0x%08X", (unsigned)hits[i]);
            if (havePe) {
                uint32_t s;
                for (s = 0; s < pe.nSections; ++s) {
                    const NrthPeSection *sec = &pe.sec[s];
                    if (hits[i] >= sec->raw && hits[i] < sec->raw + sec->rsize) {
                        printf("  %s+0x%X  rva 0x%06X", sec->name,
                               (unsigned)(hits[i] - sec->raw),
                               (unsigned)(hits[i] - sec->raw + sec->rva));
                        break;
                    }
                }
            }
            printf("\n");
        }
    }
    cli_free(buf);
    return CLI_EXIT_OK;
}

static int cli_cmd_prologue(const char *hex)
{
    uint8_t bytes[64];
    uint32_t detail = 0;
    int32_t n = cli_parse_hex(hex, bytes, sizeof(bytes));
    int32_t st;
    char st2[48];

    if (n <= 0) {
        fprintf(stderr, "[!] prologue: give 1..64 hex bytes, e.g. \"E9 FB 04 00 00\"\n");
        return CLI_EXIT_USAGE;
    }
    st = NrthClassifyPrologue(bytes, (uint32_t)n, &detail);
    if (st < 0) {
        fprintf(stderr, "[!] classification failed (status %d)\n", (int)st);
        return CLI_EXIT_USAGE;
    }
    cli_state_short((uint32_t)st, st2, sizeof(st2));
    printf("prologue : %s\nstate    : %s\n%s\ndetail   : %u (0x%X%s)\n",
           hex, cli_state_name((uint32_t)st), st2,
           (unsigned)detail, (unsigned)detail,
           st == NRTH_PRO_DETOUR_JMP32 ? " = relative target delta" : "");
    printf("tampering: %s\n", NrthPrologueIsTamper((uint32_t)st) ? "yes - detour/kill/stub footprint"
                                                                : "no  - looks like an untouched prologue");
    return NrthPrologueIsTamper((uint32_t)st) ? CLI_EXIT_FINDINGS : CLI_EXIT_OK;
}

static int cli_cmd_xor(const char *hex)
{
    uint8_t bytes[512];
    char text[640];
    uint32_t key = 0;
    int32_t n = cli_parse_hex(hex, bytes, sizeof(bytes));
    int32_t got;

    if (n <= 0) {
        fprintf(stderr, "[!] xor: give 1..512 hex bytes of the encoded record\n");
        return CLI_EXIT_USAGE;
    }
    text[0] = '\0';
    got = NrthXorCrack(bytes, (uint32_t)n, text, (uint32_t)sizeof(text), &key);
    if (got < 0) {
        fprintf(stderr, "[!] crack failed (status %d)\n", (int)got);
        return CLI_EXIT_USAGE;
    }
    printf("encoded  : %d byte(s)\nkey guess: 0x%02X%s\ndecoded  : %s (%d chars)\n",
           (int)n, (unsigned)key,
           (key == 0x2D || key == 0x20) ? " - matches the sample's codec keys" : "",
           got ? text : "<no printable run found>", (int)got);
    return CLI_EXIT_OK;
}

/* ------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    const char *cmd;
    int json = 0, showAll = 0, i;

    if (argc < 2) { cli_usage(stderr); return CLI_EXIT_USAGE; }
    cmd = argv[1];

    /* --json may appear anywhere after the command for the reporting commands */
    for (i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--json") == 0) { json = 1; argv[i] = (char *)"-"; }
        else if (strcmp(argv[i], "--all") == 0) { showAll = 1; argv[i] = (char *)"-"; }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            cli_usage(stdout);
            return CLI_EXIT_OK;
        }
    }

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        cli_usage(stdout);
        return CLI_EXIT_OK;
    }
    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0) return cli_cmd_version();
    if (strcmp(cmd, "sigs") == 0)     return cli_cmd_sigs();
    if (strcmp(cmd, "selftest") == 0) return cli_cmd_selftest(argc - 2, argv + 2);
    if (strcmp(cmd, "pe") == 0) {
        if (argc < 3) { cli_usage(stderr); return CLI_EXIT_USAGE; }
        return cli_cmd_pe(argv[2]);
    }
    if (strcmp(cmd, "audit") == 0) {
        if (argc < 3) { cli_usage(stderr); return CLI_EXIT_USAGE; }
        return cli_cmd_audit(argv[2], json);
    }
    if (strcmp(cmd, "diff") == 0) {
        if (argc < 4) { cli_usage(stderr); return CLI_EXIT_USAGE; }
        return cli_cmd_diff(argv[2], argv[3], json, showAll);
    }
    if (strcmp(cmd, "hidden") == 0) {
        uint32_t minLen = 12;
        if (argc < 3) { cli_usage(stderr); return CLI_EXIT_USAGE; }
        for (i = 3; i < argc; ++i) {
            if (argv[i][0] >= '0' && argv[i][0] <= '9') minLen = (uint32_t)atoi(argv[i]);
        }
        return cli_cmd_hidden(argv[2], minLen, json);
    }
    if (strcmp(cmd, "scan") == 0) {
        if (argc < 4) { cli_usage(stderr); return CLI_EXIT_USAGE; }
        return cli_cmd_scan(argv[2], argc - 3, argv + 3);
    }
    if (strcmp(cmd, "prologue") == 0) {
        if (argc < 3) { cli_usage(stderr); return CLI_EXIT_USAGE; }
        return cli_cmd_prologue(argv[2]);
    }
    if (strcmp(cmd, "xor") == 0) {
        if (argc < 3) { cli_usage(stderr); return CLI_EXIT_USAGE; }
        return cli_cmd_xor(argv[2]);
    }

    fprintf(stderr, "[!] unknown command '%s'\n\n", cmd);
    cli_usage(stderr);
    return CLI_EXIT_USAGE;
}
