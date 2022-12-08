/*
 * Low quality RNG.
 * The LQRNG is a simple ChaCha state with 12 words dedicated as RNG output
 * and the remaining 4 dedicated as secret state. The RNG utilizes two round
 * shuffles for updating the RNG state. The state is initialized with a single
 * 32-bit seed, but this can be improved by adding entropy (via += preferably)
 * to the LQRNG->state and calling `lqrng_mix`.
 */

#ifndef MBEDTLS_LQRNG_H 
#define MBEDTLS_LQRNG_H 

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <assert.h>
#include <stdint.h>
#include <string.h> /* memset */

#if !defined(force_inline)
#ifdef __GNUC__
#define force_inline inline __attribute__((always_inline))
#elif defined(__ARMCC_VERSION)
#define force_inline __forceinline
#else
#define force_inline inline
#endif
#endif /* force_inline */

#define MBEDTLS_AES_LQRNG_IMPL_ICHACHA2     1
#define MBEDTLS_AES_LQRNG_IMPL_ICHACHA4     2
#define MBEDTLS_AES_LQRNG_IMPL_ICHACHA6     3
#define MBEDTLS_AES_LQRNG_IMPL_ICHACHA8     4
#define MBEDTLS_AES_LQRNG_IMPL_JSF32       10
#define MBEDTLS_AES_LQRNG_IMPL_CHACHA4     22
#define MBEDTLS_AES_LQRNG_IMPL_CHACHA6     23
#define MBEDTLS_AES_LQRNG_IMPL_CHACHA8     24

#if !defined(MBEDTLS_AES_LQRNG_IMPL)
#define MBEDTLS_AES_LQRNG_IMPL MBEDTLS_AES_LQRNG_IMPL_ICHACHA4
#endif /* MBEDTLS_AES_LQRNG_IMPL */

#ifdef __cplusplus
extern "C" {
#endif

#if (   (MBEDTLS_AES_LQRNG_IMPL >= MBEDTLS_AES_LQRNG_IMPL_ICHACHA2)   \
     && (MBEDTLS_AES_LQRNG_IMPL <= MBEDTLS_AES_LQRNG_IMPL_ICHACHA8) ) \
 || (   (MBEDTLS_AES_LQRNG_IMPL >= MBEDTLS_AES_LQRNG_IMPL_CHACHA4)    \
     && (MBEDTLS_AES_LQRNG_IMPL <= MBEDTLS_AES_LQRNG_IMPL_CHACHA8) )

#if (MBEDTLS_AES_LQRNG_IMPL >= MBEDTLS_AES_LQRNG_IMPL_CHACHA4)
#define MBEDTLS_AES_LQRNG_FULL_CHACHA
#endif

#if defined(MBEDTLS_AES_LQRNG_FULL_CHACHA)
#define MBEDTLS_LQRNG_SHUFFLES (MBEDTLS_AES_LQRNG_IMPL - MBEDTLS_AES_LQRNG_IMPL_CHACHA4 + 2)

/*
 * This LQRNG is a full ChaChaX implementation
 */
#define MBEDTLS_LQRNG_IDX_MAX 64
typedef struct mbedtls_lqrng_state {
    union {
        uint32_t state[16];
        uint32_t u32_stripe[16];
        uint8_t  u8_stripe [64];
    };
    union {
        uint32_t sc[4];
        uint32_t seed[16];
    };
    int idx; /*!< Indexes u8_stripe, must be pre-aligned (to next) when used to access u32 stripe */
} mbedtls_lqrng_state;
#else  /* MBEDTLS_AES_LQRNG_FULL_CHACHA */
#define MBEDTLS_LQRNG_SHUFFLES (MBEDTLS_AES_LQRNG_IMPL - MBEDTLS_AES_LQRNG_IMPL_ICHACHA2 + 1)

/*
 * This LQRNG consists of a ChaCha state in which the first 4 words are reserved and "hidden"
 * in form of a Sponge construction.
 * If need be, u16 getter can be added without a hassle, currently it's not needed
 */
#define MBEDTLS_LQRNG_IDX_MAX 48
typedef struct mbedtls_lqrng_state {
    union {
        uint32_t state[16];
        struct {
            uint32_t sc[4];
            union {
                uint32_t u32_stripe[12];
                uint8_t  u8_stripe [48];
            };
        };
    };
    int idx; /*!< Indexes u8_stripe, must be pre-aligned (to next) when used to access u32 stripe */
} mbedtls_lqrng_state;
#endif /* MBEDTLS_AES_LQRNG_FULL_CHACHA */


/**
 * \brief Perform 2* `shuffles` ChaCha rounds on the internal state.
 * 
 * \param state    The LQRNG context. This must not be \c NULL.
 * \param shuffles Half of the number of rounds to be performed. E.g. shuffles = 1 implies two ChaCha rounds.
 */
static inline void mbedtls_lqrng_mix(mbedtls_lqrng_state* state, int shuffles)
{
    #if defined(MBEDTLS_AES_LQRNG_FULL_CHACHA)
    int x;
    /* Increment counter and then copy initial state to state buffer */
    state->seed[12]++;
    for( x = 0; x < 16; ++x )
        state->state[x] = state->seed[x];
    #endif
    #define MBEDTLS_LQRNG_ROTL(a,b) ((((a) << (b)) | ((a) >> (32 - (b)))) & 0xFFFFFFFF)
    #define MBEDTLS_LQRNG_QR(a, b, c, d) do {              \
        a += b;  d ^= a;  d = MBEDTLS_LQRNG_ROTL(d,16);    \
        c += d;  b ^= c;  b = MBEDTLS_LQRNG_ROTL(b,12);    \
        a += b;  d ^= a;  d = MBEDTLS_LQRNG_ROTL(d, 8);    \
        c += d;  b ^= c;  b = MBEDTLS_LQRNG_ROTL(b, 7);    \
        } while(0)
    for( ; shuffles > 0; --shuffles ) {
        // Odd round
        MBEDTLS_LQRNG_QR(state->state[0], state->state[4], state->state[ 8], state->state[12]); // column 0
        MBEDTLS_LQRNG_QR(state->state[1], state->state[5], state->state[ 9], state->state[13]); // column 1
        MBEDTLS_LQRNG_QR(state->state[2], state->state[6], state->state[10], state->state[14]); // column 2
        MBEDTLS_LQRNG_QR(state->state[3], state->state[7], state->state[11], state->state[15]); // column 3
        // Even round
        MBEDTLS_LQRNG_QR(state->state[0], state->state[5], state->state[10], state->state[15]); // diagonal 1
        MBEDTLS_LQRNG_QR(state->state[1], state->state[6], state->state[11], state->state[12]); // diagonal 2
        MBEDTLS_LQRNG_QR(state->state[2], state->state[7], state->state[ 8], state->state[13]); // diagonal 3
        MBEDTLS_LQRNG_QR(state->state[3], state->state[4], state->state[ 9], state->state[14]); // diagonal 4
    }
    #undef MBEDTLS_LQRNG_QR
    #undef MBEDTLS_LQRNG_ROTL
    #if defined(MBEDTLS_AES_LQRNG_FULL_CHACHA)
    for( x = 0; x < 16; ++x )
        state->state[x] += state->seed[x];
    #endif
}

#define _mbedtls_lqrng_next(ptr) do { mbedtls_lqrng_mix((ptr), MBEDTLS_LQRNG_SHUFFLES); (ptr)->idx = 0; } while(0)

static inline void mbedtls_lqrng_init(mbedtls_lqrng_state* state,
                                      const uint8_t *seed,
                                      int seed_len)
{
    static const uint32_t sc[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
    #if defined(MBEDTLS_AES_LQRNG_FULL_CHACHA)
    uint8_t *dst = (uint8_t*)&state->seed[4];
    #else  /* MBEDTLS_AES_LQRNG_FULL_CHACHA */
    uint8_t *dst = state->u8_stripe;
    #endif /* MBEDTLS_AES_LQRNG_FULL_CHACHA */
    int rem, chk;

    state->sc[ 0] = sc[0];
    state->sc[ 1] = sc[1];
    state->sc[ 2] = sc[2];
    state->sc[ 3] = sc[3];
    if(!seed_len) {
        memset(dst, 0, 48);
    }
    else {
        // Fill the remainder with seed
        for( rem = 48; rem > 0; rem -= seed_len ){
            chk = (seed_len < rem) ? seed_len : rem;
            memcpy(dst, seed, chk);
            dst += chk;
        }
    }
    #if defined(MBEDTLS_AES_LQRNG_FULL_CHACHA)
    _mbedtls_lqrng_next(state);
    #else  /* MBEDTLS_AES_LQRNG_FULL_CHACHA */
    mbedtls_lqrng_mix(state, 4);
    state->idx = 0;
    #endif  /* MBEDTLS_AES_LQRNG_FULL_CHACHA */
}

static force_inline
uint32_t mbedtls_lqrng_get32(mbedtls_lqrng_state* state)
{
    uint32_t value;

    if(state->idx & 0x3) state->idx = (state->idx - (state->idx & 0x3) + 4);
    if(state->idx >= MBEDTLS_LQRNG_IDX_MAX) _mbedtls_lqrng_next(state);
    value = state->u32_stripe[state->idx / 4];
    state->idx += 4;
    return value;
}

#define MBEDTLS_LQRNG_GETBUF_MAX_SIZE (MBEDTLS_LQRNG_IDX_MAX)
static force_inline
const uint8_t* mbedtls_lqrng_getbuf(mbedtls_lqrng_state* state, int size)
{
    const uint8_t *res;

    assert(size <= MBEDTLS_LQRNG_GETBUF_MAX_SIZE);
    if(state->idx + size > MBEDTLS_LQRNG_IDX_MAX) _mbedtls_lqrng_next(state);
    res = &state->u8_stripe[state->idx];
    state->idx += size;
    return res;
}

static force_inline
void mbedtls_lqrng_getbytes(mbedtls_lqrng_state* state, uint8_t* out, int size)
{
    int rem = MBEDTLS_LQRNG_IDX_MAX - state->idx;
    if(rem <= 0) {
        _mbedtls_lqrng_next(state); rem = MBEDTLS_LQRNG_IDX_MAX;
    }
    /* If size <= the remaining bytes in buffer, just copy size and move idx */
    if(size <= rem) {
        memcpy(out, &state->u8_stripe[state->idx], size);
        state->idx += size;
        return;
    }
    /* Otherwise, first copy all remaining bytes in buffer*/
    memcpy(out, &state->u8_stripe[state->idx], rem);
    out += rem; size -= rem;
    _mbedtls_lqrng_next(state);
    /* Then, in loop, fill as long as necessary */
    while( size > MBEDTLS_LQRNG_IDX_MAX ) {
        memcpy(out, &state->u8_stripe[state->idx], MBEDTLS_LQRNG_IDX_MAX);
        out += MBEDTLS_LQRNG_IDX_MAX; size -= MBEDTLS_LQRNG_IDX_MAX;
        _mbedtls_lqrng_next(state);
    }
    /* Final chunk */
    if( size > 0 ) {
        memcpy(out, &state->u8_stripe[state->idx], size);
        state->idx += size;
    }
}


#elif (MBEDTLS_AES_LQRNG_IMPL == MBEDTLS_AES_LQRNG_IMPL_JSF32)

/* http://burtleburtle.net/bob/rand/smallprng.html */
typedef struct mbedtls_lqrng_state {
    uint32_t x[4];
} mbedtls_lqrng_state;

static force_inline
uint32_t mbedtls_lqrng_get32(mbedtls_lqrng_state* state)
{
    #define MBEDTLS_LQRNG_ROTL(a,b) ((((a) << (b)) | ((a) >> (32 - (b)))) & 0xFFFFFFFF)
    uint32_t state_x5 = state->x[0] - MBEDTLS_LQRNG_ROTL(state->x[1], 27);
    state->x[0]       = state->x[1] ^ MBEDTLS_LQRNG_ROTL(state->x[2], 17);
    state->x[1]       = state->x[2] + state->x[3];
    state->x[2]       = state->x[3] + state_x5;
    state->x[3]       = state_x5    + state->x[0];
    return state->x[3];
    #undef MBEDTLS_LQRNG_ROTL
}

static inline void mbedtls_lqrng_init(mbedtls_lqrng_state* state,
                                      const uint8_t *seed,
                                      int seed_len)
{
    int rem, chk;
    uint8_t *dst = (uint8_t*)&state->x[1];
    state->x[0] = 0xf1ea5eed;
    if(!seed_len) {
        memset(dst, 0, 3*sizeof(uint32_t));
    }
    else {
        // Fill the remainder with seed
        for( rem = 3*sizeof(uint32_t); rem > 0; rem -= seed_len ){
            chk = (seed_len < rem) ? seed_len : rem;
            memcpy(dst, seed, chk);
            dst += chk;
        }
    }
    for( rem = 20; rem > 0; --rem) {
        (void)mbedtls_lqrng_get32(state);
    }
}

#define MBEDTLS_LQRNG_GETBUF_MAX_SIZE 0
/* mbedtls_lqrng_getbuf unsupported */

static force_inline
void mbedtls_lqrng_getbytes(mbedtls_lqrng_state* state, uint8_t* out, int size)
{
    uint8_t * const end = (out + (size & -(int)sizeof(uint32_t)));
    uint32_t tmp;
    while( out < end ) {
        tmp = mbedtls_lqrng_get32(state);
        memcpy(out, &tmp, sizeof(uint32_t));
        out += sizeof(uint32_t);
    }
    size = size & (sizeof(uint32_t)-1);
    if(size) {
        tmp = mbedtls_lqrng_get32(state);
        memcpy(out, &tmp, size);
    }
}

#endif /* MBEDTLS_AES_LQRNG_IMPL* */


#ifdef __cplusplus
}
#endif

#endif /* lqrng.h */
