#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hal.h"
#include "simpleserial.h"
#include "mbedtls/ctr_drbg.h"

#define PERSONALIZATION_LEN 8
#define CHUNK_SIZE 128
#define CHUNKS MBEDTLS_CTR_DRBG_MAX_REQUEST / CHUNK_SIZE

static mbedtls_ctr_drbg_context ctx;

static int very_good_entropy_func(void *unused, unsigned char *output, size_t len)
{
    (void) unused;
    memset(output, 0, len);
    return 0;
}

static uint8_t ctr_drbg_init(uint8_t* unused)
{
    (void) unused;
    mbedtls_ctr_drbg_init(&ctx);
    return 0x00;
}

static uint8_t ctr_drbg_seed(uint8_t* personalization)
{
    return (uint8_t)mbedtls_ctr_drbg_seed(&ctx , very_good_entropy_func, NULL, personalization, PERSONALIZATION_LEN);
}


static uint8_t rbuf[MBEDTLS_CTR_DRBG_SEEDLEN];
static uint8_t get_seed(uint8_t* unused)
{
    (void) unused;
    memcpy(rbuf, ctx.aes_ctx.rk, MBEDTLS_CTR_DRBG_KEYSIZE);
    memcpy(rbuf + MBEDTLS_CTR_DRBG_KEYSIZE, ctx.counter, MBEDTLS_CTR_DRBG_BLOCKSIZE);
    simpleserial_put('r', MBEDTLS_CTR_DRBG_SEEDLEN, rbuf);
    return 0x00;
}

static uint8_t set_seed(uint8_t* seed)
{
    uint8_t ret = (uint8_t)mbedtls_aes_setkey_enc(&ctx.aes_ctx, seed, MBEDTLS_CTR_DRBG_KEYBITS);
    memcpy(ctx.counter, seed + MBEDTLS_CTR_DRBG_KEYSIZE, MBEDTLS_CTR_DRBG_BLOCKSIZE);
    return ret;
}

static uint8_t outbuf[MBEDTLS_CTR_DRBG_MAX_REQUEST];
static uint8_t ctr_drbg_random(uint8_t* unused)
{
    (void) unused;
    trigger_high();
    uint8_t rc = (uint8_t)mbedtls_ctr_drbg_random(&ctx, outbuf, MBEDTLS_CTR_DRBG_MAX_REQUEST);
    trigger_low();
    return rc;
}

static uint8_t read_chunk(uint8_t* num)
{
    uint8_t n = num[0];
    simpleserial_put('r', CHUNK_SIZE, outbuf + n * CHUNK_SIZE);
    return 0x00;
}

static uint8_t ctr_drbg_free(uint8_t* unused)
{
    (void) unused;
    mbedtls_ctr_drbg_free(&ctx);
    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    simpleserial_init();
    simpleserial_addcmd('i', 0,                        ctr_drbg_init);
    simpleserial_addcmd('s', PERSONALIZATION_LEN,      ctr_drbg_seed);
    simpleserial_addcmd('g', 0,                        ctr_drbg_random);
    simpleserial_addcmd('f', 0,                        ctr_drbg_free);
    simpleserial_addcmd('r', 1,                        read_chunk);
    simpleserial_addcmd('x', 0,                        get_seed);
    simpleserial_addcmd('y', MBEDTLS_CTR_DRBG_SEEDLEN, set_seed);

    while(1)
    {
        simpleserial_get();
    }
}
