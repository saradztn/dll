/**
 * ============================================================================
 * nrth_audit.h — PUBLIC CONTRACT of the NORTH/NVX defensive audit module
 * ============================================================================
 * Result class: R2 (newly authored defensive code) built on D2 evidence.
 *
 * WHAT THIS MODULE DELIBERATELY DOES NOT DO (blue-team scope decision):
 * - it never opens another process, never injects, never hooks, never changes memory
 *   protection, never writes a byte outside its own caller-provided output buffers;
 * - it cannot execute Lua in a game VM and contains no script payload, no feature
 *   logic, no overlay, no loader, no self-protection and no evasion;
 * - it reads one file (a module copy, or a memory-dump the team already owns) and
 *   reports where the tool's hook targets are and whether a prologue looks patched.
 *
 * Version 1.2.0 (2026-10-11)
 * ============================================================================
 */
#ifndef NRTH_AUDIT_H
#define NRTH_AUDIT_H

#include <stdint.h>

#ifdef _WIN32
#  if defined(NRTH_AUDIT_BUILD)
#    define NRTH_AUDIT_API __declspec(dllexport)
#  elif defined(NRTH_AUDIT_STATIC)
#    define NRTH_AUDIT_API
#  else
#    define NRTH_AUDIT_API __declspec(dllimport)
#  endif
#else
#  define NRTH_AUDIT_API
#endif

/* C linkage marker: the module is callable from plain C, so the marker must
   vanish when this header is consumed by a C compiler (MSVC/clang/gcc all
   reject `extern "C"` in C translation units). */
#ifdef __cplusplus
#  define NRTH_AUDIT_C extern "C"
#else
#  define NRTH_AUDIT_C
#endif

#define NRTH_AUDIT_VERSION "1.2.0"

/* ---- status codes -------------------------------------------------------- */
#define NVXA_OK             0
#define NVXA_E_INVALID     -1
#define NVXA_E_FORMAT      -2
#define NVXA_E_TRUNCATED   -3
#define NVXA_E_IO          -4

/* ---- prologue states ----------------------------------------------------- */
typedef enum _NrthPrologueState {
    NRTH_PRO_UNKNOWN          = 0,
    NRTH_PRO_PRISTINE         = 1,
    NRTH_PRO_DETOUR_JMP32     = 2,
    NRTH_PRO_DETOUR_FARJMP    = 3,
    NRTH_PRO_DETOUR_PUSHRET   = 4,
    NRTH_PRO_KILL_RET         = 5,
    NRTH_PRO_KILL_RETN        = 6,
    NRTH_PRO_STUB_IMM         = 7,
    NRTH_PRO_PAD              = 8,
    NRTH_PRO_JMP_INDIRECT     = 9
} NrthPrologueState;

/* ---- verified signature catalogue ---------------------------------------- */
typedef struct _NrthSignature {
    uint32_t    id;
    const char *pattern;
    const char *target;
    const char *role;
    uint32_t    decryptor_va;
    uint32_t    pattern_len;
    uint32_t    xor_key;
    uint32_t    confidence;
    const char *evidence;
} NrthSignature;

/* ---- one result row per catalogue signature ------------------------------ */
typedef struct _NrthSigFinding {
    uint32_t sigId;
    uint32_t fullHits;
    uint32_t patchedHits;
    uint32_t firstFullRva;
    uint32_t firstPatchedRva;
    uint32_t state;
    uint32_t detail;
    uint32_t textSectionOnly;
} NrthSigFinding;

/* ---- minimal PE view ----------------------------------------------------- */
#define NRTH_PE_MAX_SECTIONS 96
typedef struct _NrthPeSection {
    char     name[9];
    uint32_t rva, vsize, raw, rsize, characteristics;
} NrthPeSection;

typedef struct _NrthPeView {
    const uint8_t   *img;
    uint32_t         size;
    uint32_t         imageBase;
    uint32_t         entryRva;
    uint32_t         timestamp;
    uint16_t         machine;
    uint16_t         nSections;
    uint32_t         characteristics;
    int              mapped;
    NrthPeSection    sec[NRTH_PE_MAX_SECTIONS];
} NrthPeView;

#ifdef __cplusplus
extern "C" {
#endif

NRTH_AUDIT_C NRTH_AUDIT_API const char *NrthAuditVersion(void);
NRTH_AUDIT_C NRTH_AUDIT_API uint32_t NrthSigCount(void);
NRTH_AUDIT_C NRTH_AUDIT_API const NrthSignature *NrthSigAt(uint32_t i);
NRTH_AUDIT_C NRTH_AUDIT_API const char *NrthPrologueStateName(uint32_t state);
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthPrologueIsTamper(uint32_t state);

NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthXorTransform(const uint8_t *in, uint32_t len,
                                                     uint32_t key, uint8_t *out,
                                                     uint32_t outCap);
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthXorCrack(const uint8_t *in, uint32_t len,
                                                 char *text, uint32_t textCap,
                                                 uint32_t *outKey);
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthXorDecodeRecordAt(const NrthPeView *pe,
                                                          uint32_t va, uint32_t len,
                                                          char *text, uint32_t textCap,
                                                          uint32_t *outKey);

NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthPatCompile(const char *text, uint8_t *bytes,
                                                   uint8_t *mask, uint32_t cap,
                                                   uint32_t *outLen);
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthPatScan(const uint8_t *buf, uint32_t len,
                                                const char *pattern, uint32_t *hits,
                                                uint32_t maxHits);
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthPatWidenHead(const char *pattern, uint32_t head,
                                                     char *out, uint32_t outCap);
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthPatPatchHead(const char *pattern, uint32_t head,
                                                     const char *footprint,
                                                     char *out, uint32_t outCap);

NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthClassifyPrologue(const uint8_t *func, uint32_t avail,
                                                         uint32_t *outDetail);

NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthPeMap(const uint8_t *img, uint32_t size,
                                              NrthPeView *out);
NRTH_AUDIT_C NRTH_AUDIT_API const uint8_t *NrthPeSectionData(const NrthPeView *pe,
                                                             uint32_t sectionIndex,
                                                             uint32_t *outLen,
                                                             uint32_t *outRva);
NRTH_AUDIT_C NRTH_AUDIT_API const uint8_t *NrthPeRvaToPtr(const NrthPeView *pe,
                                                          uint32_t rva, uint32_t want);
NRTH_AUDIT_C NRTH_AUDIT_API uint32_t NrthPeTextRva(const NrthPeView *pe);

NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthAuditImage(const uint8_t *img, uint32_t size,
                                                   NrthSigFinding *findings,
                                                   uint32_t maxFindings);
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthAuditImageFile(const char *path,
                                                       NrthSigFinding *findings,
                                                       uint32_t maxFindings);

typedef struct _NrthAuditDiffRow {
    uint32_t sigId;
    uint32_t cleanFull;
    uint32_t cleanPatched;
    uint32_t susFull;
    uint32_t susPatched;
    uint32_t susState;
    uint32_t susRva;
    uint32_t susDetail;
    uint32_t addedFootprint;
    uint32_t targetLost;
    uint32_t susUnlocated;
} NrthAuditDiffRow;

NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthAuditDiff(const uint8_t *cleanImg, uint32_t cleanSize,
                                                  const uint8_t *susImg, uint32_t susSize,
                                                  NrthAuditDiffRow *rows, uint32_t maxRows);
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthAuditDiffFiles(const char *cleanPath,
                                                       const char *susPath,
                                                       NrthAuditDiffRow *rows,
                                                       uint32_t maxRows);

NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthFindHiddenSignatures(const uint8_t *img, uint32_t size,
                                                             uint32_t minLen,
                                                             char *textOut, uint32_t textCap,
                                                             uint32_t *outVas,
                                                             uint32_t maxVas);

NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthAuditSelfTest(char *report, uint32_t reportCap);

#ifdef __cplusplus
}
#endif

#endif /* NRTH_AUDIT_H */