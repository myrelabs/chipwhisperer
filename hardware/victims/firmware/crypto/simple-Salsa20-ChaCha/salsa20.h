#ifndef SALSA20_H
#define SALSA20_H

#include <stdint.h>

typedef struct salsa_context {
    uint32_t state[16];
    uint32_t key[8];
    uint32_t ctr[2];
    uint32_t nonce[2];
} salsa_context_t;
typedef salsa_context_t chacha_context_t;

void salsa20_setkey(salsa_context_t *ctx, uint8_t *key);
void salsa20_getblock(salsa_context_t *ctx, uint64_t nonce, uint64_t counter, uint8_t *out);

#define chacha_setkey salsa20_setkey
void chacha_getblock(chacha_context_t *ctx, uint64_t nonce, uint64_t counter, uint8_t *out);

#endif // SALSA20_H
