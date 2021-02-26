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

#if HWCRYPTO

void aes_indep_init(void)
{
    HW_AES128_Init();
}

void aes_indep_key(uint8_t * key)
{
    HW_AES128_LoadKey(key);
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    HW_AES128_Enc_pretrigger(pt);
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    HW_AES128_Enc_posttrigger(pt);
}

void aes_indep_enc(uint8_t * pt)
{
    HW_AES128_Enc(pt);
}

#ifdef AES_DECRYPT
void aes_indep_dec_pretrigger(uint8_t * pt)
{
    HW_AES128_Dec_pretrigger(pt);
}

void aes_indep_dec_posttrigger(uint8_t * pt)
{
    HW_AES128_Dec_posttrigger(pt);
}

void aes_indep_dec(uint8_t * pt)
{
    HW_AES128_Dec(pt);
}
#endif

void aes_indep_mask(uint8_t * m)
{
}

#elif defined(AVRCRYPTOLIB)
#include "aes128_enc.h"
#include "aes128_dec.h"
#include "aes_keyschedule.h"

aes128_ctx_t ctx;

void aes_indep_init(void)
{
	;
}

void aes_indep_key(uint8_t * key)
{
	aes128_init(key, &ctx);
}

void aes_indep_enc(uint8_t * pt)
{
	aes128_enc(pt, &ctx); /* encrypting the data block */
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

#ifdef AES_DECRYPT
void aes_indep_dec(uint8_t * pt)
{
	aes128_dec(pt, &ctx); /* encrypting the data block */
}

void aes_indep_dec_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_dec_posttrigger(uint8_t * pt)
{
    ;
}
#endif

void aes_indep_mask(uint8_t * m)
{
}

#elif defined(SIMPLEAES)

uint8_t enckey[16];

void aes_indep_init(void)
{
	;
}

void aes_indep_key(uint8_t * key)
{
	for(uint8_t i=0; i < 16; i++){
		enckey[i] = key[i];
	}
}

void aes_indep_enc(uint8_t * pt)
{
	uint8_t * result = aes(pt, enckey);
	for(uint8_t i=0; i < 16; i++){
		pt[i] = result[i];
	}
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_mask(uint8_t * m)
{
}

#elif defined(DPAV4)

#include "aes.h"
#include "aes_enc.h"

/*  This is the AES RSM 256 encryption function that call the generic AES RSM encryption core*/
void aes256_enc(uint8_t* j, void* buffer, aes256_ctx_t* ctx,uint8_t rng){
	aes_encrypt_core(j,buffer, (aes_genctx_t*)ctx, 14,(uint8_t)rng);
}

aes256_ctx_t ctx;

void aes_indep_init(void)
{
    ;
}

void aes_indep_key(uint8_t * key)
{
	aes256_init(key, &ctx);
}

void aes_indep_enc(uint8_t * pt)
{
	static uint8_t j[0];

	//Encryption with trigger enabled
	aes256_enc(j, pt, &ctx, 1);
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_mask(uint8_t * m)
{
}

#elif defined(TINYAES128C)

#include "aes.h"

uint8_t enckey[16];

void aes_indep_init(void)
{
	;
}

void aes_indep_key(uint8_t * key)
{
    AES128_ECB_indp_setkey(key);
}

void aes_indep_enc(uint8_t * pt)
{
	AES128_ECB_indp_crypto(pt);
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_mask(uint8_t * m)
{
}

#elif defined(MBEDTLS)
#include "mbedtls/aes.h"

static mbedtls_aes_context enc_ctx;
#ifdef AES_DECRYPT
static mbedtls_aes_context dec_ctx;
#endif

void aes_indep_init(void)
{
	mbedtls_aes_init(&enc_ctx);
    #ifdef AES_DECRYPT
    mbedtls_aes_init(&dec_ctx);
    #endif
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_key(uint8_t * key)
{
	mbedtls_aes_setkey_enc(&enc_ctx, key, 128);
    #ifdef AES_DECRYPT
	mbedtls_aes_setkey_dec(&dec_ctx, key, 128);
    #endif
}

void aes_indep_enc(uint8_t * pt)
{
	mbedtls_aes_crypt_ecb(&enc_ctx, MBEDTLS_AES_ENCRYPT, pt, pt); /* encrypting the data block */
}

#ifdef AES_DECRYPT
void aes_indep_dec_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_dec_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_dec(uint8_t * ct)
{
	mbedtls_aes_crypt_ecb(&dec_ctx, MBEDTLS_AES_DECRYPT, ct, ct); /* decrypting the data block */
}
#endif

void aes_indep_mask(uint8_t * m)
{
}

#elif defined(WOLFSSL)

// FIXME: add target-dependent default headers
#include <user_settings_arm.h>
#include <wolfssl/wolfcrypt/aes.h>

static Aes enc_ctx;
#ifdef AES_DECRYPT
static Aes dec_ctx;
#endif

void aes_indep_init(void)
{
	wc_AesInit(&enc_ctx, NULL, INVALID_DEVID);
    #ifdef AES_DECRYPT
    wc_AesInit(&dec_ctx, NULL, INVALID_DEVID);
    #endif
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_key(uint8_t * key)
{
    uint8_t t[16] = {0};
	wc_AesSetKeyDirect(&enc_ctx, key, 16, t, AES_ENCRYPTION);
    #ifdef AES_DECRYPT
	wc_AesSetKeyDirect(&dec_ctx, key, 16, t, AES_DECRYPTION);
    #endif
}

void aes_indep_enc(uint8_t * pt)
{
    uint8_t t[16];
    wc_AesEncryptDirect(&enc_ctx, t, pt); /* encrypting the data block */
    memcpy(pt, t, 16);
}

#ifdef AES_DECRYPT
void aes_indep_dec_pretrigger(uint8_t * pt)
{
    ;
}

void aes_indep_dec_posttrigger(uint8_t * pt)
{
    ;
}

void aes_indep_dec(uint8_t * ct)
{
	wc_AesDecryptDirect(&dec_ctx, ct, ct); /* decrypting the data block */
}
#endif

void aes_indep_mask(uint8_t * m)
{
}

#elif defined(MASKEDAES)

#include "aesTables.h"
#include "maskedAES128enc.h"

void aes_indep_init(void)
{
}

void aes_indep_key(uint8_t * key)
{
  int i;
  for (i = 0; i < AESKeySize; i++)
    secret[i] = key[i];
}

void aes_indep_enc(uint8_t * pt)
{
  asm_maskedAES128enc();
}

void aes_indep_enc_pretrigger(uint8_t * pt)
{
  int i;
  for (i = 0; i < AESInputSize; i++)
    input[i] = pt[i];
}

void aes_indep_enc_posttrigger(uint8_t * pt)
{
    int i;
  for (i = 0; i < AESOutputSize; i++)
    pt[i] = input[i];
}

void aes_indep_mask(uint8_t * m)
{
  int i;
  for (i = 0; i < AESMaskSize; i++)
    mask[i] = m[i];
}



#else

#error "No Crypto Lib Defined?"

#endif


