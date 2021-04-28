/*
    This file is part of the AESExplorer Example Targets
    Copyright (C) 2012 Colin O'Flynn <coflynn@newae.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "aes-independant.h"
#include "hal.h"

#if defined(SIMPLESALSA)

#include "salsa20.h"
#include <string.h>

chacha_context_t ctx;

void chacha_indep_init(void)
{
	;
}

void chacha_indep_key(uint8_t * key)
{
    chacha_setkey(&ctx, key);
}

void chacha_indep_block(uint8_t * in, uint8_t * out)
{
    uint64_t nonce, ctr;
    memcpy(&ctr,   in,   8);
    memcpy(&nonce, in+8, 8);
    chacha_getblock(&ctx, nonce, ctr, out);
}

#elif defined(MBEDTLS)
#include "mbedtls/chacha20.h"
#include <string.h>

static mbedtls_chacha20_context ctx;

void chacha_indep_init(void)
{
    mbedtls_chacha20_init(&ctx);
}

void chacha_indep_key(uint8_t * key)
{
    mbedtls_chacha20_setkey(&ctx, key);
}

void chacha_indep_block(uint8_t * in, uint8_t * out)
{
    uint32_t ctr;
    memcpy(&ctr, in, 4);
    memset(out, 0, 64);
    mbedtls_chacha20_starts(&ctx, in + 4, ctr);
    mbedtls_chacha20_update(&ctx, 64, out, out);
}

#elif defined(WOLFSSL)

// FIXME: add target-dependent default headers
#include <user_settings_arm.h>
#include <wolfssl/wolfcrypt/aes.h>

static Aes enc_ctx;

void aes_indep_init(void)
{
	wc_AesInit(&enc_ctx, NULL, INVALID_DEVID);
}

void chacha_indep_key(uint8_t * key)
{
    uint8_t t[16] = {0};
	wc_AesSetKeyDirect(&enc_ctx, key, 16, t, AES_ENCRYPTION);
}

void chacha_indep_block(uint8_t * pt)
{
    uint8_t t[16];
    wc_AesEncryptDirect(&enc_ctx, t, pt); /* encrypting the data block */
    memcpy(pt, t, 16);
}

#else

#error "No Crypto Lib Defined?"

#endif


