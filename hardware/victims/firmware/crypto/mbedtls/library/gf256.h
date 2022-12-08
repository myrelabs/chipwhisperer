#ifndef MBEDTLS_GF256_H
#define MBEDTLS_GF256_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/aes.h"

#include <stdint.h>

#if defined(MBEDTLS_AES_GF256_FORCE_INLINE)
    #define MBEDTLS_GF256_INLINE force_inline
#else
    #define MBEDTLS_GF256_INLINE inline
#endif /* MBEDTLS_AES_GF256_FORCE_INLINE */

#define MBEDTLS_AES_GF256_IMPL_LU_4x4   0
#define MBEDTLS_AES_GF256_IMPL_LU_4x4x3 1
#define MBEDTLS_AES_GF256_IMPL_LU_4x8   2
#define MBEDTLS_AES_GF256_IMPL_LU_4x8x2 3
#define MBEDTLS_AES_GF256_IMPL_ALOG     4

#if !defined(MBEDTLS_AES_GF256_IMPL)
#define MBEDTLS_AES_GF256_IMPL MBEDTLS_AES_GF256_IMPL_ALOG
#endif /* MBEDTLS_AES_GF256_IMPL */


#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_AES_ROM_TABLES)
#define TABLE_STORAGE extern const
#else
#define TABLE_STORAGE extern
void gf256_gen_tables(int pow[255], int log[256]);
#endif

#if ((MBEDTLS_AES_GF256_IMPL == MBEDTLS_AES_GF256_IMPL_LU_4x4) \
  || (MBEDTLS_AES_GF256_IMPL == MBEDTLS_AES_GF256_IMPL_LU_4x8))
/** \brief Lookup higher bits of 8bit x 8bit mul, xor the value to the lower half for a reduced mul */
TABLE_STORAGE uint8_t gf256_red_lu[128];
#define MBEDTLS_HAVE_GF256_RED_LU
#endif /* MBEDTLS_AES_GF256_IMPL_LU_4x4 || MBEDTLS_AES_GF256_IMPL_LU_4x8 */

#if ((MBEDTLS_AES_GF256_IMPL == MBEDTLS_AES_GF256_IMPL_LU_4x4) \
  || (MBEDTLS_AES_GF256_IMPL == MBEDTLS_AES_GF256_IMPL_LU_4x4x3))
/** \brief 4bit x 4bit gf256 mul lookup table; combine four for a full 8bit x 8bit mul. */
TABLE_STORAGE uint8_t gf256_mul_lu_4x4_ll[256];
#define MBEDTLS_HAVE_GF256_MUL_LU_4x4_LL
#if (MBEDTLS_AES_GF256_IMPL == MBEDTLS_AES_GF256_IMPL_LU_4x4x3)

/** \brief 4bit x 4bit, middle (*2^4) gf256 mul lookup table, reduced. */
TABLE_STORAGE uint8_t gf256_mul_lu_4x4_lh[256];
#define MBEDTLS_HAVE_GF256_MUL_LU_4x4_LH
/** \brief 4bit x 4bit, high (*2^8) gf256 mul lookup table, reduced. */
TABLE_STORAGE uint8_t gf256_mul_lu_4x4_hh[256];
#define MBEDTLS_HAVE_GF256_MUL_LU_4x4_HH
#endif /* MBEDTLS_AES_GF256_IMPL_LU_4x4x3 */

static MBEDTLS_GF256_INLINE uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    #if (MBEDTLS_AES_GF256_IMPL == MBEDTLS_AES_GF256_IMPL_LU_4x4)
    uint16_t c;
    c =      (uint16_t)gf256_mul_lu_4x4_ll[((a & 0x0F) << 4) | ((b & 0x0F))]
      ^ ((   (uint16_t)gf256_mul_lu_4x4_ll[((a & 0x0F)     ) | ((b & 0xF0))]
           ^ (uint16_t)gf256_mul_lu_4x4_ll[((a & 0xF0)     ) | ((b & 0x0F))] ) << 4)
      ^ (    (uint16_t)gf256_mul_lu_4x4_ll[((a & 0xF0) >> 4) | ((b & 0xF0))]   << 8);
    return (c & 0xFF) ^ gf256_red_lu[c >> 8];
    #else
    return gf256_mul_lu_4x4_ll[((a & 0x0F) << 4) | ((b & 0x0F))]
         ^ gf256_mul_lu_4x4_lh[((a & 0x0F)     ) | ((b & 0xF0))]
         ^ gf256_mul_lu_4x4_lh[((a & 0xF0)     ) | ((b & 0x0F))]
         ^ gf256_mul_lu_4x4_hh[((a & 0xF0) >> 4) | ((b & 0xF0))];
    #endif
}

#elif (MBEDTLS_AES_GF256_IMPL == MBEDTLS_AES_GF256_IMPL_ALOG)

/** \brief Lookup table for logarithm with base 3 (primitive element x+1), with log3(0) = 0. */
TABLE_STORAGE uint8_t gf256_log3_lu[256];
#define MBEDTLS_HAVE_GF256_LOG3_LU

/** \brief Exponent lookup of 3 (primitive element x+1), repeated twice. */
TABLE_STORAGE uint8_t gf256_exp3_lu[2*255];
#define MBEDTLS_HAVE_GF256_EXP3_LU

static MBEDTLS_GF256_INLINE uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    uint8_t s;
    int e, m;
    e = gf256_log3_lu[a] + gf256_log3_lu[b]; 
    /* Get the antilog (exp) */
    s = gf256_exp3_lu[e];
    m  = (int)(a) - 1;
    m |= (int)(b) - 1;
    return s & ~(m >> 8); /* On ARM this can be done in one instruction: bic [s], [m], asr #8 */
}

#else /* MBEDTLS_AES_GF256_IMPL_LU_4x8 || MBEDTLS_AES_GF256_IMPL_LU_4x8x2 */
/** \brief 4bit x 8bit gf256 mul lookup table; combine two for a full 8bit x 8bit mul */
TABLE_STORAGE uint8_t gf256_mul_lu_4x8_l[256*16];
#define MBEDTLS_HAVE_GF256_MUL_LU_4x8_L
#if (MBEDTLS_AES_GF256_IMPL == MBEDTLS_AES_GF256_IMPL_LU_4x8x2)
/** \brief 4bit x 8bit, high (*2^4) gf256 mul lookup table, reduced */
TABLE_STORAGE uint8_t gf256_mul_lu_4x8_h[256*16];
#define MBEDTLS_HAVE_GF256_MUL_LU_4x8_H
#endif /* MBEDTLS_AES_GF256_IMPL_LU_4x8x2 */

static MBEDTLS_GF256_INLINE uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    #if (MBEDTLS_AES_GF256_IMPL == MBEDTLS_AES_GF256_IMPL_LU_4x8x2)
    uint16_t cl, ch;
    cl = gf256_mul_lu_4x8_l[(int)a << 4 | (b & 0xF)];
    ch = gf256_mul_lu_4x8_h[(int)a << 4 | (b >>  4)];
    return cl ^ ch;
    #else /* MBEDTLS_AES_GF256_IMPL_LU_4x8x2 */
    uint16_t c, cl, ch;
    cl = gf256_mul_lu_4x8_l[(int)a << 4 | (b & 0xF)];
    ch = gf256_mul_lu_4x8_l[(int)a << 4 | (b >>  4)];
    c = cl ^ (ch << 4);
    return (c & 0xFF) ^ gf256_red_lu[c >> 8];
    #endif /* MBEDTLS_AES_GF256_IMPL_LU_4x8x2 */
}
#endif

/** \brief All 8bit squares in gf256 */
TABLE_STORAGE uint8_t gf256_sqr_lu[256];
#define MBEDTLS_HAVE_GF256_SQR_LU
#define gf256_sqr(x) (gf256_sqr_lu[(x)])

#undef MBEDTLS_GF256_INLINE

#ifdef __cplusplus
}
#endif

#endif /* gf256.h */
