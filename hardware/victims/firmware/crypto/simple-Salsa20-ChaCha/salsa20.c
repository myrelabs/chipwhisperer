/*
 * Simple Salsa20 and ChaCha implementations.
 * Based on https://en.wikipedia.org/wiki/Salsa20
 */

#include <stdint.h>

#include "salsa20.h"

/* Constant "expand 32-byte k" */
static const uint32_t sc[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

#define ROTL(a,b) ((((a) << (b)) | ((a) >> (32 - (b)))) & 0xFFFFFFFF)

#define QR(a, b, c, d) do { \
    b ^= ROTL(a + d, 7);    \
    c ^= ROTL(b + a, 9);    \
    d ^= ROTL(c + b,13);    \
    a ^= ROTL(d + c,18);    \
    } while (0)
#define ROUNDS 20

#define STATE_CONTEXT_MAP(op) do { \
        ctx->state[ 0] op sc[0];   \
        ctx->state[ 5] op sc[1];   \
        ctx->state[10] op sc[2];   \
        ctx->state[15] op sc[3];   \
        ctx->state[ 1] op ctx->key[0];    \
        ctx->state[ 2] op ctx->key[1];    \
        ctx->state[ 3] op ctx->key[2];    \
        ctx->state[ 4] op ctx->key[3];    \
        ctx->state[11] op ctx->key[4];    \
        ctx->state[12] op ctx->key[5];    \
        ctx->state[13] op ctx->key[6];    \
        ctx->state[14] op ctx->key[7];    \
        ctx->state[ 6] op ctx->nonce[0];  \
        ctx->state[ 7] op ctx->nonce[1];  \
        ctx->state[ 8] op ctx->ctr[0];    \
        ctx->state[ 9] op ctx->ctr[1];    \
    } while(0)
 
void salsa20_block(salsa_context_t* ctx)
{
    int i;
    STATE_CONTEXT_MAP(=);
    // 10 loops × 2 rounds/loop = 20 rounds
    for (i = 0; i < ROUNDS; i += 2) {
        // Odd round
        QR(ctx->state[ 0], ctx->state[ 4], ctx->state[ 8], ctx->state[12]);    // column 1
        QR(ctx->state[ 5], ctx->state[ 9], ctx->state[13], ctx->state[ 1]);    // column 2
        QR(ctx->state[10], ctx->state[14], ctx->state[ 2], ctx->state[ 6]);    // column 3
        QR(ctx->state[15], ctx->state[ 3], ctx->state[ 7], ctx->state[11]);    // column 4
        // Even round
        QR(ctx->state[ 0], ctx->state[ 1], ctx->state[ 2], ctx->state[ 3]);    // row 1
        QR(ctx->state[ 5], ctx->state[ 6], ctx->state[ 7], ctx->state[ 4]);    // row 2
        QR(ctx->state[10], ctx->state[11], ctx->state[ 8], ctx->state[ 9]);    // row 3
        QR(ctx->state[15], ctx->state[12], ctx->state[13], ctx->state[14]);    // row 4
    }
    STATE_CONTEXT_MAP(+=);
}

#undef QR
#undef ROUNDS
#undef STATE_CONTEXT_MAP


#define QR(a, b, c, d) do {              \
    a += b;  d ^= a;  d = ROTL(d,16);    \
    c += d;  b ^= c;  b = ROTL(b,12);    \
    a += b;  d ^= a;  d = ROTL(d, 8);    \
    c += d;  b ^= c;  b = ROTL(b, 7);    \
    } while(0)
#define ROUNDS 20

#define STATE_CONTEXT_MAP(op) do { \
        ctx->state[ 0] op sc[0];   \
        ctx->state[ 1] op sc[1];   \
        ctx->state[ 2] op sc[2];   \
        ctx->state[ 3] op sc[3];   \
        ctx->state[ 4] op ctx->key[0];    \
        ctx->state[ 5] op ctx->key[1];    \
        ctx->state[ 6] op ctx->key[2];    \
        ctx->state[ 7] op ctx->key[3];    \
        ctx->state[ 8] op ctx->key[4];    \
        ctx->state[ 9] op ctx->key[5];    \
        ctx->state[10] op ctx->key[6];    \
        ctx->state[11] op ctx->key[7];    \
        ctx->state[12] op ctx->ctr[0];    \
        ctx->state[13] op ctx->ctr[1];    \
        ctx->state[14] op ctx->nonce[0];  \
        ctx->state[15] op ctx->nonce[1];  \
    } while(0)
 
void chacha_block(chacha_context_t* ctx)
{
    int i;
    STATE_CONTEXT_MAP(=);
    // 10 loops × 2 rounds/loop = 20 rounds
    for (i = 0; i < ROUNDS; i += 2) {
        // Odd round
        QR(ctx->state[0], ctx->state[4], ctx->state[ 8], ctx->state[12]); // column 0
        QR(ctx->state[1], ctx->state[5], ctx->state[ 9], ctx->state[13]); // column 1
        QR(ctx->state[2], ctx->state[6], ctx->state[10], ctx->state[14]); // column 2
        QR(ctx->state[3], ctx->state[7], ctx->state[11], ctx->state[15]); // column 3
        // Even round
        QR(ctx->state[0], ctx->state[5], ctx->state[10], ctx->state[15]); // diagonal 1 (main diagonal)
        QR(ctx->state[1], ctx->state[6], ctx->state[11], ctx->state[12]); // diagonal 2
        QR(ctx->state[2], ctx->state[7], ctx->state[ 8], ctx->state[13]); // diagonal 3
        QR(ctx->state[3], ctx->state[4], ctx->state[ 9], ctx->state[14]); // diagonal 4
    }
    STATE_CONTEXT_MAP(+=);
}

#undef QR
#undef ROUNDS
#undef STATE_CONTEXT_MAP

#define LOAD_LE_32(a)      ( ((uint32_t)(*(a)))           + \
                             ((uint32_t)(*((a)+1)) <<  8) + \
                             ((uint32_t)(*((a)+2)) << 16) + \
                             ((uint32_t)(*((a)+3)) << 24) )
#define STORE_LE_32(a, v)  do {            \
        *((a)+0) = (  (v)        & 0xFF ); \
        *((a)+1) = ( ((v) >>  8) & 0xFF ); \
        *((a)+2) = ( ((v) >> 16) & 0xFF ); \
        *((a)+3) = ( ((v) >> 24) & 0xFF ); \
    } while(0)

void salsa20_setkey(salsa_context_t *ctx, uint8_t *key)
{
    ctx->key[0] = LOAD_LE_32(key +  0);
    ctx->key[1] = LOAD_LE_32(key +  4);
    ctx->key[2] = LOAD_LE_32(key +  8);
    ctx->key[3] = LOAD_LE_32(key + 12);
    ctx->key[4] = LOAD_LE_32(key + 16);
    ctx->key[5] = LOAD_LE_32(key + 20);
    ctx->key[6] = LOAD_LE_32(key + 24);
    ctx->key[7] = LOAD_LE_32(key + 28);
}

typedef void (*block_function_t)(salsa_context_t *ctx);

#define GETBLOCK(bf) do { \
        ctx->ctr[0]   = (uint32_t)((counter)       & 0xFFFFFFFFu); \
        ctx->ctr[1]   = (uint32_t)((counter >> 32) & 0xFFFFFFFFu); \
        ctx->nonce[0] = (uint32_t)((nonce)         & 0xFFFFFFFFu); \
        ctx->nonce[1] = (uint32_t)((nonce >> 32)   & 0xFFFFFFFFu); \
        bf(ctx);          \
        STORE_LE_32(out +  0, ctx->state[ 0]); \
        STORE_LE_32(out +  4, ctx->state[ 1]); \
        STORE_LE_32(out +  8, ctx->state[ 2]); \
        STORE_LE_32(out + 12, ctx->state[ 3]); \
        STORE_LE_32(out + 16, ctx->state[ 4]); \
        STORE_LE_32(out + 20, ctx->state[ 5]); \
        STORE_LE_32(out + 24, ctx->state[ 6]); \
        STORE_LE_32(out + 28, ctx->state[ 7]); \
        STORE_LE_32(out + 32, ctx->state[ 8]); \
        STORE_LE_32(out + 36, ctx->state[ 9]); \
        STORE_LE_32(out + 40, ctx->state[10]); \
        STORE_LE_32(out + 44, ctx->state[11]); \
        STORE_LE_32(out + 48, ctx->state[12]); \
        STORE_LE_32(out + 52, ctx->state[13]); \
        STORE_LE_32(out + 56, ctx->state[14]); \
        STORE_LE_32(out + 60, ctx->state[15]); \
    } while(0)

void salsa20_getblock(salsa_context_t *ctx, uint64_t nonce, uint64_t counter, uint8_t *out)
{
    GETBLOCK(salsa20_block);
}

void chacha_getblock(chacha_context_t *ctx, uint64_t nonce, uint64_t counter, uint8_t *out)
{
    GETBLOCK(chacha_block);
}
