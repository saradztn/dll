#pragma once
/**
 * ============================================================================
 * nrth_codec.h — Positional-XOR string codec (matches original NRTH.dll)
 * ============================================================================
 * Original decryptors: 0x100078d0 (scalar, key 0x2D) and 0x1000bc00 (SSE, key 0x20)
 * Transform: out[p] = in[p] ^ ((p - key) & 0xFF)
 * Symmetric: encode == decode.
 * ============================================================================
 */
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void NrthXorTransform(const uint8_t *in, size_t len, uint8_t key, uint8_t *out)
{
    for (size_t p = 0; p < len; ++p)
        out[p] = (uint8_t)(in[p] ^ (uint8_t)(p - key));
}

#ifdef __cplusplus
}
#endif