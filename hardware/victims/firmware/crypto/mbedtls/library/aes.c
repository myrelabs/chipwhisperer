/*
 *  FIPS-197 compliant AES implementation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
/*
 *  The AES block cipher was designed by Vincent Rijmen and Joan Daemen.
 *
 *  http://csrc.nist.gov/encryption/aes/rijndael/Rijndael.pdf
 *  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */
#ifdef __x86_64__
#include <x86intrin.h>
#else
#include <stm32f3xx.h>
#define __rdtsc() (DWT->CYCCNT)
#endif

#include "common.h"

#if defined(MBEDTLS_AES_C)

#include <string.h>
#include "gf256.h"

#include "mbedtls/aes.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#if defined(MBEDTLS_PADLOCK_C)
#include "mbedtls/padlock.h"
#endif
#if defined(MBEDTLS_AESNI_C)
#include "mbedtls/aesni.h"
#endif

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#if !defined(MBEDTLS_AES_ALT)

/* Parameter validation macros based on platform_util.h */
#define AES_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_AES_BAD_INPUT_DATA )
#define AES_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                                    \
{                                                               \
    (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
    (b)[(i) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
    (b)[(i) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
}
#endif

#if defined(MBEDTLS_PADLOCK_C) &&                      \
    ( defined(MBEDTLS_HAVE_X86) || defined(MBEDTLS_PADLOCK_ALIGN16) )
static int aes_padlock_ace = -1;
#endif

#if defined(MBEDTLS_AES_ROM_TABLES)
/*
 * Forward S-box
 */
static const unsigned char FSb[256] =
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/*
 * Forward tables
 */
#define FT \
\
    V(A5,63,63,C6), V(84,7C,7C,F8), V(99,77,77,EE), V(8D,7B,7B,F6), \
    V(0D,F2,F2,FF), V(BD,6B,6B,D6), V(B1,6F,6F,DE), V(54,C5,C5,91), \
    V(50,30,30,60), V(03,01,01,02), V(A9,67,67,CE), V(7D,2B,2B,56), \
    V(19,FE,FE,E7), V(62,D7,D7,B5), V(E6,AB,AB,4D), V(9A,76,76,EC), \
    V(45,CA,CA,8F), V(9D,82,82,1F), V(40,C9,C9,89), V(87,7D,7D,FA), \
    V(15,FA,FA,EF), V(EB,59,59,B2), V(C9,47,47,8E), V(0B,F0,F0,FB), \
    V(EC,AD,AD,41), V(67,D4,D4,B3), V(FD,A2,A2,5F), V(EA,AF,AF,45), \
    V(BF,9C,9C,23), V(F7,A4,A4,53), V(96,72,72,E4), V(5B,C0,C0,9B), \
    V(C2,B7,B7,75), V(1C,FD,FD,E1), V(AE,93,93,3D), V(6A,26,26,4C), \
    V(5A,36,36,6C), V(41,3F,3F,7E), V(02,F7,F7,F5), V(4F,CC,CC,83), \
    V(5C,34,34,68), V(F4,A5,A5,51), V(34,E5,E5,D1), V(08,F1,F1,F9), \
    V(93,71,71,E2), V(73,D8,D8,AB), V(53,31,31,62), V(3F,15,15,2A), \
    V(0C,04,04,08), V(52,C7,C7,95), V(65,23,23,46), V(5E,C3,C3,9D), \
    V(28,18,18,30), V(A1,96,96,37), V(0F,05,05,0A), V(B5,9A,9A,2F), \
    V(09,07,07,0E), V(36,12,12,24), V(9B,80,80,1B), V(3D,E2,E2,DF), \
    V(26,EB,EB,CD), V(69,27,27,4E), V(CD,B2,B2,7F), V(9F,75,75,EA), \
    V(1B,09,09,12), V(9E,83,83,1D), V(74,2C,2C,58), V(2E,1A,1A,34), \
    V(2D,1B,1B,36), V(B2,6E,6E,DC), V(EE,5A,5A,B4), V(FB,A0,A0,5B), \
    V(F6,52,52,A4), V(4D,3B,3B,76), V(61,D6,D6,B7), V(CE,B3,B3,7D), \
    V(7B,29,29,52), V(3E,E3,E3,DD), V(71,2F,2F,5E), V(97,84,84,13), \
    V(F5,53,53,A6), V(68,D1,D1,B9), V(00,00,00,00), V(2C,ED,ED,C1), \
    V(60,20,20,40), V(1F,FC,FC,E3), V(C8,B1,B1,79), V(ED,5B,5B,B6), \
    V(BE,6A,6A,D4), V(46,CB,CB,8D), V(D9,BE,BE,67), V(4B,39,39,72), \
    V(DE,4A,4A,94), V(D4,4C,4C,98), V(E8,58,58,B0), V(4A,CF,CF,85), \
    V(6B,D0,D0,BB), V(2A,EF,EF,C5), V(E5,AA,AA,4F), V(16,FB,FB,ED), \
    V(C5,43,43,86), V(D7,4D,4D,9A), V(55,33,33,66), V(94,85,85,11), \
    V(CF,45,45,8A), V(10,F9,F9,E9), V(06,02,02,04), V(81,7F,7F,FE), \
    V(F0,50,50,A0), V(44,3C,3C,78), V(BA,9F,9F,25), V(E3,A8,A8,4B), \
    V(F3,51,51,A2), V(FE,A3,A3,5D), V(C0,40,40,80), V(8A,8F,8F,05), \
    V(AD,92,92,3F), V(BC,9D,9D,21), V(48,38,38,70), V(04,F5,F5,F1), \
    V(DF,BC,BC,63), V(C1,B6,B6,77), V(75,DA,DA,AF), V(63,21,21,42), \
    V(30,10,10,20), V(1A,FF,FF,E5), V(0E,F3,F3,FD), V(6D,D2,D2,BF), \
    V(4C,CD,CD,81), V(14,0C,0C,18), V(35,13,13,26), V(2F,EC,EC,C3), \
    V(E1,5F,5F,BE), V(A2,97,97,35), V(CC,44,44,88), V(39,17,17,2E), \
    V(57,C4,C4,93), V(F2,A7,A7,55), V(82,7E,7E,FC), V(47,3D,3D,7A), \
    V(AC,64,64,C8), V(E7,5D,5D,BA), V(2B,19,19,32), V(95,73,73,E6), \
    V(A0,60,60,C0), V(98,81,81,19), V(D1,4F,4F,9E), V(7F,DC,DC,A3), \
    V(66,22,22,44), V(7E,2A,2A,54), V(AB,90,90,3B), V(83,88,88,0B), \
    V(CA,46,46,8C), V(29,EE,EE,C7), V(D3,B8,B8,6B), V(3C,14,14,28), \
    V(79,DE,DE,A7), V(E2,5E,5E,BC), V(1D,0B,0B,16), V(76,DB,DB,AD), \
    V(3B,E0,E0,DB), V(56,32,32,64), V(4E,3A,3A,74), V(1E,0A,0A,14), \
    V(DB,49,49,92), V(0A,06,06,0C), V(6C,24,24,48), V(E4,5C,5C,B8), \
    V(5D,C2,C2,9F), V(6E,D3,D3,BD), V(EF,AC,AC,43), V(A6,62,62,C4), \
    V(A8,91,91,39), V(A4,95,95,31), V(37,E4,E4,D3), V(8B,79,79,F2), \
    V(32,E7,E7,D5), V(43,C8,C8,8B), V(59,37,37,6E), V(B7,6D,6D,DA), \
    V(8C,8D,8D,01), V(64,D5,D5,B1), V(D2,4E,4E,9C), V(E0,A9,A9,49), \
    V(B4,6C,6C,D8), V(FA,56,56,AC), V(07,F4,F4,F3), V(25,EA,EA,CF), \
    V(AF,65,65,CA), V(8E,7A,7A,F4), V(E9,AE,AE,47), V(18,08,08,10), \
    V(D5,BA,BA,6F), V(88,78,78,F0), V(6F,25,25,4A), V(72,2E,2E,5C), \
    V(24,1C,1C,38), V(F1,A6,A6,57), V(C7,B4,B4,73), V(51,C6,C6,97), \
    V(23,E8,E8,CB), V(7C,DD,DD,A1), V(9C,74,74,E8), V(21,1F,1F,3E), \
    V(DD,4B,4B,96), V(DC,BD,BD,61), V(86,8B,8B,0D), V(85,8A,8A,0F), \
    V(90,70,70,E0), V(42,3E,3E,7C), V(C4,B5,B5,71), V(AA,66,66,CC), \
    V(D8,48,48,90), V(05,03,03,06), V(01,F6,F6,F7), V(12,0E,0E,1C), \
    V(A3,61,61,C2), V(5F,35,35,6A), V(F9,57,57,AE), V(D0,B9,B9,69), \
    V(91,86,86,17), V(58,C1,C1,99), V(27,1D,1D,3A), V(B9,9E,9E,27), \
    V(38,E1,E1,D9), V(13,F8,F8,EB), V(B3,98,98,2B), V(33,11,11,22), \
    V(BB,69,69,D2), V(70,D9,D9,A9), V(89,8E,8E,07), V(A7,94,94,33), \
    V(B6,9B,9B,2D), V(22,1E,1E,3C), V(92,87,87,15), V(20,E9,E9,C9), \
    V(49,CE,CE,87), V(FF,55,55,AA), V(78,28,28,50), V(7A,DF,DF,A5), \
    V(8F,8C,8C,03), V(F8,A1,A1,59), V(80,89,89,09), V(17,0D,0D,1A), \
    V(DA,BF,BF,65), V(31,E6,E6,D7), V(C6,42,42,84), V(B8,68,68,D0), \
    V(C3,41,41,82), V(B0,99,99,29), V(77,2D,2D,5A), V(11,0F,0F,1E), \
    V(CB,B0,B0,7B), V(FC,54,54,A8), V(D6,BB,BB,6D), V(3A,16,16,2C)

#define V(a,b,c,d) 0x##a##b##c##d
static const uint32_t FT0[256] = { FT };
#undef V

#if !defined(MBEDTLS_AES_FEWER_TABLES)

#define V(a,b,c,d) 0x##b##c##d##a
static const uint32_t FT1[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const uint32_t FT2[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const uint32_t FT3[256] = { FT };
#undef V

#endif /* !MBEDTLS_AES_FEWER_TABLES */

#undef FT

/*
 * Reverse S-box
 */
static const unsigned char RSb[256] =
{
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

/*
 * Reverse tables
 */
#define RT \
\
    V(50,A7,F4,51), V(53,65,41,7E), V(C3,A4,17,1A), V(96,5E,27,3A), \
    V(CB,6B,AB,3B), V(F1,45,9D,1F), V(AB,58,FA,AC), V(93,03,E3,4B), \
    V(55,FA,30,20), V(F6,6D,76,AD), V(91,76,CC,88), V(25,4C,02,F5), \
    V(FC,D7,E5,4F), V(D7,CB,2A,C5), V(80,44,35,26), V(8F,A3,62,B5), \
    V(49,5A,B1,DE), V(67,1B,BA,25), V(98,0E,EA,45), V(E1,C0,FE,5D), \
    V(02,75,2F,C3), V(12,F0,4C,81), V(A3,97,46,8D), V(C6,F9,D3,6B), \
    V(E7,5F,8F,03), V(95,9C,92,15), V(EB,7A,6D,BF), V(DA,59,52,95), \
    V(2D,83,BE,D4), V(D3,21,74,58), V(29,69,E0,49), V(44,C8,C9,8E), \
    V(6A,89,C2,75), V(78,79,8E,F4), V(6B,3E,58,99), V(DD,71,B9,27), \
    V(B6,4F,E1,BE), V(17,AD,88,F0), V(66,AC,20,C9), V(B4,3A,CE,7D), \
    V(18,4A,DF,63), V(82,31,1A,E5), V(60,33,51,97), V(45,7F,53,62), \
    V(E0,77,64,B1), V(84,AE,6B,BB), V(1C,A0,81,FE), V(94,2B,08,F9), \
    V(58,68,48,70), V(19,FD,45,8F), V(87,6C,DE,94), V(B7,F8,7B,52), \
    V(23,D3,73,AB), V(E2,02,4B,72), V(57,8F,1F,E3), V(2A,AB,55,66), \
    V(07,28,EB,B2), V(03,C2,B5,2F), V(9A,7B,C5,86), V(A5,08,37,D3), \
    V(F2,87,28,30), V(B2,A5,BF,23), V(BA,6A,03,02), V(5C,82,16,ED), \
    V(2B,1C,CF,8A), V(92,B4,79,A7), V(F0,F2,07,F3), V(A1,E2,69,4E), \
    V(CD,F4,DA,65), V(D5,BE,05,06), V(1F,62,34,D1), V(8A,FE,A6,C4), \
    V(9D,53,2E,34), V(A0,55,F3,A2), V(32,E1,8A,05), V(75,EB,F6,A4), \
    V(39,EC,83,0B), V(AA,EF,60,40), V(06,9F,71,5E), V(51,10,6E,BD), \
    V(F9,8A,21,3E), V(3D,06,DD,96), V(AE,05,3E,DD), V(46,BD,E6,4D), \
    V(B5,8D,54,91), V(05,5D,C4,71), V(6F,D4,06,04), V(FF,15,50,60), \
    V(24,FB,98,19), V(97,E9,BD,D6), V(CC,43,40,89), V(77,9E,D9,67), \
    V(BD,42,E8,B0), V(88,8B,89,07), V(38,5B,19,E7), V(DB,EE,C8,79), \
    V(47,0A,7C,A1), V(E9,0F,42,7C), V(C9,1E,84,F8), V(00,00,00,00), \
    V(83,86,80,09), V(48,ED,2B,32), V(AC,70,11,1E), V(4E,72,5A,6C), \
    V(FB,FF,0E,FD), V(56,38,85,0F), V(1E,D5,AE,3D), V(27,39,2D,36), \
    V(64,D9,0F,0A), V(21,A6,5C,68), V(D1,54,5B,9B), V(3A,2E,36,24), \
    V(B1,67,0A,0C), V(0F,E7,57,93), V(D2,96,EE,B4), V(9E,91,9B,1B), \
    V(4F,C5,C0,80), V(A2,20,DC,61), V(69,4B,77,5A), V(16,1A,12,1C), \
    V(0A,BA,93,E2), V(E5,2A,A0,C0), V(43,E0,22,3C), V(1D,17,1B,12), \
    V(0B,0D,09,0E), V(AD,C7,8B,F2), V(B9,A8,B6,2D), V(C8,A9,1E,14), \
    V(85,19,F1,57), V(4C,07,75,AF), V(BB,DD,99,EE), V(FD,60,7F,A3), \
    V(9F,26,01,F7), V(BC,F5,72,5C), V(C5,3B,66,44), V(34,7E,FB,5B), \
    V(76,29,43,8B), V(DC,C6,23,CB), V(68,FC,ED,B6), V(63,F1,E4,B8), \
    V(CA,DC,31,D7), V(10,85,63,42), V(40,22,97,13), V(20,11,C6,84), \
    V(7D,24,4A,85), V(F8,3D,BB,D2), V(11,32,F9,AE), V(6D,A1,29,C7), \
    V(4B,2F,9E,1D), V(F3,30,B2,DC), V(EC,52,86,0D), V(D0,E3,C1,77), \
    V(6C,16,B3,2B), V(99,B9,70,A9), V(FA,48,94,11), V(22,64,E9,47), \
    V(C4,8C,FC,A8), V(1A,3F,F0,A0), V(D8,2C,7D,56), V(EF,90,33,22), \
    V(C7,4E,49,87), V(C1,D1,38,D9), V(FE,A2,CA,8C), V(36,0B,D4,98), \
    V(CF,81,F5,A6), V(28,DE,7A,A5), V(26,8E,B7,DA), V(A4,BF,AD,3F), \
    V(E4,9D,3A,2C), V(0D,92,78,50), V(9B,CC,5F,6A), V(62,46,7E,54), \
    V(C2,13,8D,F6), V(E8,B8,D8,90), V(5E,F7,39,2E), V(F5,AF,C3,82), \
    V(BE,80,5D,9F), V(7C,93,D0,69), V(A9,2D,D5,6F), V(B3,12,25,CF), \
    V(3B,99,AC,C8), V(A7,7D,18,10), V(6E,63,9C,E8), V(7B,BB,3B,DB), \
    V(09,78,26,CD), V(F4,18,59,6E), V(01,B7,9A,EC), V(A8,9A,4F,83), \
    V(65,6E,95,E6), V(7E,E6,FF,AA), V(08,CF,BC,21), V(E6,E8,15,EF), \
    V(D9,9B,E7,BA), V(CE,36,6F,4A), V(D4,09,9F,EA), V(D6,7C,B0,29), \
    V(AF,B2,A4,31), V(31,23,3F,2A), V(30,94,A5,C6), V(C0,66,A2,35), \
    V(37,BC,4E,74), V(A6,CA,82,FC), V(B0,D0,90,E0), V(15,D8,A7,33), \
    V(4A,98,04,F1), V(F7,DA,EC,41), V(0E,50,CD,7F), V(2F,F6,91,17), \
    V(8D,D6,4D,76), V(4D,B0,EF,43), V(54,4D,AA,CC), V(DF,04,96,E4), \
    V(E3,B5,D1,9E), V(1B,88,6A,4C), V(B8,1F,2C,C1), V(7F,51,65,46), \
    V(04,EA,5E,9D), V(5D,35,8C,01), V(73,74,87,FA), V(2E,41,0B,FB), \
    V(5A,1D,67,B3), V(52,D2,DB,92), V(33,56,10,E9), V(13,47,D6,6D), \
    V(8C,61,D7,9A), V(7A,0C,A1,37), V(8E,14,F8,59), V(89,3C,13,EB), \
    V(EE,27,A9,CE), V(35,C9,61,B7), V(ED,E5,1C,E1), V(3C,B1,47,7A), \
    V(59,DF,D2,9C), V(3F,73,F2,55), V(79,CE,14,18), V(BF,37,C7,73), \
    V(EA,CD,F7,53), V(5B,AA,FD,5F), V(14,6F,3D,DF), V(86,DB,44,78), \
    V(81,F3,AF,CA), V(3E,C4,68,B9), V(2C,34,24,38), V(5F,40,A3,C2), \
    V(72,C3,1D,16), V(0C,25,E2,BC), V(8B,49,3C,28), V(41,95,0D,FF), \
    V(71,01,A8,39), V(DE,B3,0C,08), V(9C,E4,B4,D8), V(90,C1,56,64), \
    V(61,84,CB,7B), V(70,B6,32,D5), V(74,5C,6C,48), V(42,57,B8,D0)

#define V(a,b,c,d) 0x##a##b##c##d
static const uint32_t RT0[256] = { RT };
#undef V

#if !defined(MBEDTLS_AES_FEWER_TABLES)

#define V(a,b,c,d) 0x##b##c##d##a
static const uint32_t RT1[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const uint32_t RT2[256] = { RT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const uint32_t RT3[256] = { RT };
#undef V

#endif /* !MBEDTLS_AES_FEWER_TABLES */

#undef RT

/*
 * Round constants
 */
static const uint32_t RCON[10] =
{
    0x00000001, 0x00000002, 0x00000004, 0x00000008,
    0x00000010, 0x00000020, 0x00000040, 0x00000080,
    0x0000001B, 0x00000036
};

#else /* MBEDTLS_AES_ROM_TABLES */

/*
 * Forward S-box & tables
 */
static unsigned char FSb[256];
static uint32_t FT0[256];
#if !defined(MBEDTLS_AES_FEWER_TABLES)
static uint32_t FT1[256];
static uint32_t FT2[256];
static uint32_t FT3[256];
#endif /* !MBEDTLS_AES_FEWER_TABLES */

/*
 * Reverse S-box & tables
 */
static unsigned char RSb[256];
static uint32_t RT0[256];
#if !defined(MBEDTLS_AES_FEWER_TABLES)
static uint32_t RT1[256];
static uint32_t RT2[256];
static uint32_t RT3[256];
#endif /* !MBEDTLS_AES_FEWER_TABLES */

/*
 * Round constants
 */
static uint32_t RCON[10];

/*
 * Tables generation code
 */
#define ROTL8(x) ( ( (x) << 8 ) & 0xFFFFFFFF ) | ( (x) >> 24 )
#define XTIME(x) ( ( (x) << 1 ) ^ ( ( (x) & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( (x) && (y) ) ? pow[(log[(x)]+log[(y)]) % 255] : 0 )

static int aes_init_done = 0;

static void aes_gen_tables( void )
{
    int i, x, y, z;
    int pow[256];
    int log[256];

    /*
     * compute pow and log tables over GF(2^8)
     */
    for( i = 0, x = 1; i < 256; i++ )
    {
        pow[i] = x;
        log[x] = i;
        x = ( x ^ XTIME( x ) ) & 0xFF;
    }

    /*
     * calculate the round constants
     */
    for( i = 0, x = 1; i < 10; i++ )
    {
        RCON[i] = (uint32_t) x;
        x = XTIME( x ) & 0xFF;
    }

    /*
     * generate the forward and reverse S-boxes
     */
    FSb[0x00] = 0x63;
    RSb[0x63] = 0x00;

    for( i = 1; i < 256; i++ )
    {
        x = pow[255 - log[i]];

        y  = x; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y ^ 0x63;

        FSb[i] = (unsigned char) x;
        RSb[x] = (unsigned char) i;
    }

    /*
     * generate the forward and reverse tables
     */
    for( i = 0; i < 256; i++ )
    {
        x = FSb[i];
        y = XTIME( x ) & 0xFF;
        z =  ( y ^ x ) & 0xFF;

        FT0[i] = ( (uint32_t) y       ) ^
                 ( (uint32_t) x <<  8 ) ^
                 ( (uint32_t) x << 16 ) ^
                 ( (uint32_t) z << 24 );

#if !defined(MBEDTLS_AES_FEWER_TABLES)
        FT1[i] = ROTL8( FT0[i] );
        FT2[i] = ROTL8( FT1[i] );
        FT3[i] = ROTL8( FT2[i] );
#endif /* !MBEDTLS_AES_FEWER_TABLES */

        x = RSb[i];

        RT0[i] = ( (uint32_t) MUL( 0x0E, x )       ) ^
                 ( (uint32_t) MUL( 0x09, x ) <<  8 ) ^
                 ( (uint32_t) MUL( 0x0D, x ) << 16 ) ^
                 ( (uint32_t) MUL( 0x0B, x ) << 24 );

#if !defined(MBEDTLS_AES_FEWER_TABLES)
        RT1[i] = ROTL8( RT0[i] );
        RT2[i] = ROTL8( RT1[i] );
        RT3[i] = ROTL8( RT2[i] );
#endif /* !MBEDTLS_AES_FEWER_TABLES */
    }
}

#undef ROTL8

#endif /* MBEDTLS_AES_ROM_TABLES */

#if defined(MBEDTLS_AES_FEWER_TABLES)

#define ROTL8(x)  ( (uint32_t)( ( x ) <<  8 ) + (uint32_t)( ( x ) >> 24 ) )
#define ROTL16(x) ( (uint32_t)( ( x ) << 16 ) + (uint32_t)( ( x ) >> 16 ) )
#define ROTL24(x) ( (uint32_t)( ( x ) << 24 ) + (uint32_t)( ( x ) >>  8 ) )

#define AES_RT0(idx) RT0[idx]
#define AES_RT1(idx) ROTL8(  RT0[idx] )
#define AES_RT2(idx) ROTL16( RT0[idx] )
#define AES_RT3(idx) ROTL24( RT0[idx] )

#define AES_FT0(idx) FT0[idx]
#define AES_FT1(idx) ROTL8(  FT0[idx] )
#define AES_FT2(idx) ROTL16( FT0[idx] )
#define AES_FT3(idx) ROTL24( FT0[idx] )

#else /* MBEDTLS_AES_FEWER_TABLES */

#define AES_RT0(idx) RT0[idx]
#define AES_RT1(idx) RT1[idx]
#define AES_RT2(idx) RT2[idx]
#define AES_RT3(idx) RT3[idx]

#define AES_FT0(idx) FT0[idx]
#define AES_FT1(idx) FT1[idx]
#define AES_FT2(idx) FT2[idx]
#define AES_FT3(idx) FT3[idx]

#endif /* MBEDTLS_AES_FEWER_TABLES */

void mbedtls_aes_init( mbedtls_aes_context *ctx )
{
    AES_VALIDATE( ctx != NULL );

    memset( ctx, 0, sizeof( mbedtls_aes_context ) );
}

void mbedtls_aes_free( mbedtls_aes_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_aes_context ) );
}

#if defined(MBEDTLS_CIPHER_MODE_XTS)
void mbedtls_aes_xts_init( mbedtls_aes_xts_context *ctx )
{
    AES_VALIDATE( ctx != NULL );

    mbedtls_aes_init( &ctx->crypt );
    mbedtls_aes_init( &ctx->tweak );
}

void mbedtls_aes_xts_free( mbedtls_aes_xts_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_aes_free( &ctx->crypt );
    mbedtls_aes_free( &ctx->tweak );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

/*
 * AES key schedule (encryption)
 */
#if !defined(MBEDTLS_AES_SETKEY_ENC_ALT)
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    unsigned int i;
    uint32_t *RK;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    switch( keybits )
    {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

#if !defined(MBEDTLS_AES_ROM_TABLES)
    if( aes_init_done == 0 )
    {
        aes_gen_tables();
        aes_init_done = 1;
    }
#endif

#if defined(MBEDTLS_PADLOCK_C) && defined(MBEDTLS_PADLOCK_ALIGN16)
    if( aes_padlock_ace == -1 )
        aes_padlock_ace = mbedtls_padlock_has_support( MBEDTLS_PADLOCK_ACE );

    if( aes_padlock_ace )
        ctx->rk = RK = MBEDTLS_PADLOCK_ALIGN16( ctx->buf );
    else
#endif
    ctx->rk = RK = ctx->buf;

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_AES ) )
        return( mbedtls_aesni_setkey_enc( (unsigned char *) ctx->rk, key, keybits ) );
#endif

    for( i = 0; i < ( keybits >> 5 ); i++ )
    {
        GET_UINT32_LE( RK[i], key, i << 2 );
    }

    switch( ctx->nr )
    {
        case 10:

            for( i = 0; i < 10; i++, RK += 4 )
            {
                RK[4]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[3] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[3]       ) & 0xFF ] << 24 );

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

        case 12:

            for( i = 0; i < 8; i++, RK += 6 )
            {
                RK[6]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[5] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[5]       ) & 0xFF ] << 24 );

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:

            for( i = 0; i < 7; i++, RK += 8 )
            {
                RK[8]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[7] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[7]       ) & 0xFF ] << 24 );

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];

                RK[12] = RK[4] ^
                ( (uint32_t) FSb[ ( RK[11]       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[11] >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 24 ) & 0xFF ] << 24 );

                RK[13] = RK[5] ^ RK[12];
                RK[14] = RK[6] ^ RK[13];
                RK[15] = RK[7] ^ RK[14];
            }
            break;
    }

    return( 0 );
}
#endif /* !MBEDTLS_AES_SETKEY_ENC_ALT */

/*
 * AES key schedule (decryption)
 */
#if !defined(MBEDTLS_AES_SETKEY_DEC_ALT)
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    int i, j, ret;
    mbedtls_aes_context cty;
    uint32_t *RK;
    uint32_t *SK;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    mbedtls_aes_init( &cty );

#if defined(MBEDTLS_PADLOCK_C) && defined(MBEDTLS_PADLOCK_ALIGN16)
    if( aes_padlock_ace == -1 )
        aes_padlock_ace = mbedtls_padlock_has_support( MBEDTLS_PADLOCK_ACE );

    if( aes_padlock_ace )
        ctx->rk = RK = MBEDTLS_PADLOCK_ALIGN16( ctx->buf );
    else
#endif
    ctx->rk = RK = ctx->buf;

    /* Also checks keybits */
    if( ( ret = mbedtls_aes_setkey_enc( &cty, key, keybits ) ) != 0 )
        goto exit;

    ctx->nr = cty.nr;

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_AES ) )
    {
        mbedtls_aesni_inverse_key( (unsigned char *) ctx->rk,
                           (const unsigned char *) cty.rk, ctx->nr );
        goto exit;
    }
#endif

    SK = cty.rk + cty.nr * 4;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    for( i = ctx->nr - 1, SK -= 8; i > 0; i--, SK -= 8 )
    {
        for( j = 0; j < 4; j++, SK++ )
        {
            *RK++ = AES_RT0( FSb[ ( *SK       ) & 0xFF ] ) ^
                    AES_RT1( FSb[ ( *SK >>  8 ) & 0xFF ] ) ^
                    AES_RT2( FSb[ ( *SK >> 16 ) & 0xFF ] ) ^
                    AES_RT3( FSb[ ( *SK >> 24 ) & 0xFF ] );
        }
    }

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

exit:
    mbedtls_aes_free( &cty );

    return( ret );
}
#endif /* !MBEDTLS_AES_SETKEY_DEC_ALT */

#if defined(MBEDTLS_CIPHER_MODE_XTS)
static int mbedtls_aes_xts_decode_keys( const unsigned char *key,
                                        unsigned int keybits,
                                        const unsigned char **key1,
                                        unsigned int *key1bits,
                                        const unsigned char **key2,
                                        unsigned int *key2bits )
{
    const unsigned int half_keybits = keybits / 2;
    const unsigned int half_keybytes = half_keybits / 8;

    switch( keybits )
    {
        case 256: break;
        case 512: break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    *key1bits = half_keybits;
    *key2bits = half_keybits;
    *key1 = &key[0];
    *key2 = &key[half_keybytes];

    return 0;
}

int mbedtls_aes_xts_setkey_enc( mbedtls_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *key1, *key2;
    unsigned int key1bits, key2bits;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    ret = mbedtls_aes_xts_decode_keys( key, keybits, &key1, &key1bits,
                                       &key2, &key2bits );
    if( ret != 0 )
        return( ret );

    /* Set the tweak key. Always set tweak key for the encryption mode. */
    ret = mbedtls_aes_setkey_enc( &ctx->tweak, key2, key2bits );
    if( ret != 0 )
        return( ret );

    /* Set crypt key for encryption. */
    return mbedtls_aes_setkey_enc( &ctx->crypt, key1, key1bits );
}

int mbedtls_aes_xts_setkey_dec( mbedtls_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *key1, *key2;
    unsigned int key1bits, key2bits;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    ret = mbedtls_aes_xts_decode_keys( key, keybits, &key1, &key1bits,
                                       &key2, &key2bits );
    if( ret != 0 )
        return( ret );

    /* Set the tweak key. Always set tweak key for encryption. */
    ret = mbedtls_aes_setkey_enc( &ctx->tweak, key2, key2bits );
    if( ret != 0 )
        return( ret );

    /* Set crypt key for decryption. */
    return mbedtls_aes_setkey_dec( &ctx->crypt, key1, key1bits );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */


/*
 * Low quality RNG segment.
 * The LQRNG is a simple ChaCha state with 12 words dedicated as RNG output
 * and the remaining 4 dedicated as secret state. The RNG utilizes two round
 * shuffles for updating the RNG state. The state is initialized with a single
 * 32-bit seed, but this can be improved by adding entropy (via += preferably)
 * to the LQRNG->state and calling `lqrng_mix`.
 */
#define LQRNG_MAX_IDX 48
typedef struct lqrng_state {
    union {
        uint32_t state[16];
        uint32_t u32_stripe[12];
        uint16_t u16_stripe[24];
        uint8_t  u8_stripe [48];
    };
    int idx;
} lqrng_state;

static inline void lqrng_mix(uint32_t* restrict state, int shuffles)
{
    #define ROTL(a,b) ((((a) << (b)) | ((a) >> (32 - (b)))) & 0xFFFFFFFF)
    #define QR(a, b, c, d) do {              \
        a += b;  d ^= a;  d = ROTL(d,16);    \
        c += d;  b ^= c;  b = ROTL(b,12);    \
        a += b;  d ^= a;  d = ROTL(d, 8);    \
        c += d;  b ^= c;  b = ROTL(b, 7);    \
        } while(0)
    for( ; shuffles > 0; --shuffles ) {
        // Odd round
        QR(state[0], state[4], state[ 8], state[12]); // column 0
        QR(state[1], state[5], state[ 9], state[13]); // column 1
        QR(state[2], state[6], state[10], state[14]); // column 2
        QR(state[3], state[7], state[11], state[15]); // column 3
        // Even round
        QR(state[0], state[5], state[10], state[15]); // diagonal 1
        QR(state[1], state[6], state[11], state[12]); // diagonal 2
        QR(state[2], state[7], state[ 8], state[13]); // diagonal 3
        QR(state[3], state[4], state[ 9], state[14]); // diagonal 4
    }
    #undef QR
    #undef ROTL
}

static inline void lqrng_init(lqrng_state* state, uint32_t seed)
{
    static const uint32_t sc[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
    state->state[ 0] = sc[0];
    state->state[ 1] = sc[1];
    state->state[ 2] = sc[2];
    state->state[ 3] = sc[3];
    state->state[ 4] = seed;
    state->state[ 5] = seed;
    state->state[ 6] = seed;
    state->state[ 7] = seed;
    memset(&state->state[8], 0, 8 * sizeof(uint32_t));
    lqrng_mix(state->state, 4);
    state->idx = 0;
}

#define _lqrng_next(ptr) do { lqrng_mix((ptr)->state, 1); (ptr)->idx = 0; } while(0)

__attribute__((always_inline))
static inline uint32_t lqrng_get32(lqrng_state* state)
{
    /* Get next u32-aligned idx */
    state->idx = (state->idx + 4) & 0xFFFFFFFC;
    if(state->idx >= LQRNG_MAX_IDX) _lqrng_next(state);
    return state->u32_stripe[state->idx / 4];
}

__attribute__((always_inline))
static inline uint16_t lqrng_get16(lqrng_state* state)
{
    /* Get next u16-aligned idx */
    state->idx = (state->idx + 2) & 0xFFFFFFFE;
    if(state->idx >= LQRNG_MAX_IDX) _lqrng_next(state);
    return state->u16_stripe[state->idx / 2];
}

__attribute__((always_inline))
static inline uint8_t lqrng_get8(lqrng_state* state)
{
    /* Get next u8-aligned idx */
    state->idx = (state->idx + 1);
    if(state->idx >= LQRNG_MAX_IDX) _lqrng_next(state);
    return state->u8_stripe[state->idx];
}

#define LQRNG_GETBUF_MAX_SIZE LQRNG_MAX_IDX
__attribute__((always_inline))
static inline const uint8_t* lqrng_getbuf(lqrng_state* state, int size)
{
    assert(size <= LQRNG_GETBUF_MAX_SIZE);
    if(state->idx + size > LQRNG_MAX_IDX) _lqrng_next(state);
    const uint8_t *res = &state->u8_stripe[state->idx];
    state->idx += size;
    return res;
}


#define UNROLL_LOOP _Pragma("GCC unroll 16")
// #define UNROLL_LOOP


/* Masking based on https://eprint.iacr.org/2010/441.pdf */


#define MBEDTLS_AES_NTH_ORD_MASK
#define MBEDTLS_AES_NTH_ORD_MASK_ORDER  2
#define MBEDTLS_AES_NTH_ORD_MASK_ROUNDS 2

#define MBEDTLS_AES_AFFINE_LOOKUP 1

/*
 * Random bytes:
 * (MBEDTLS_AES_NTH_ORD_MASK_ORDER*(MBEDTLS_AES_NTH_ORD_MASK_ORDER-1))/2
 */
#define MASKED_SEC_MULT_RANDBYTES ((MBEDTLS_AES_NTH_ORD_MASK_ORDER*(MBEDTLS_AES_NTH_ORD_MASK_ORDER-1))/2)
#define MASKED_SEC_MULT(Cs,As,Bs,RB) do {    \
    uint8_t $r[MBEDTLS_AES_NTH_ORD_MASK_ORDER][MBEDTLS_AES_NTH_ORD_MASK_ORDER]; \
    int $x,$y;                                                                  \
    uint8_t $tmp;                                                               \
    UNROLL_LOOP for( $x = 0; $x<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++$x ){         \
        UNROLL_LOOP for( $y = $x+1; $y<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++$y){   \
            $tmp = *(RB)++;                                           \
            $r[$x][$y] = gf256_mul(As[$x], Bs[$y]) ^ $tmp;                      \
            $r[$y][$x] = gf256_mul(As[$y], Bs[$x]) ^ $tmp;                      \
        }                                                                       \
    }                                                                           \
    UNROLL_LOOP for( $x = 0; $x<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++$x ){         \
        Cs[$x] = gf256_mul(As[$x], Bs[$x]);                                     \
        UNROLL_LOOP for( $y = 0; $y<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++$y ) {    \
            if ($y != $x) {                                                     \
                Cs[$x] ^= $r[$x][$y];                                           \
            }                                                                   \
        }                                                                       \
    }                                                                           \
} while ( 0 )

#ifdef MBEDTLS_AES_AFFINE_LOOKUP
static const uint8_t aes_affine[256] = {
    0x63, 0x7c, 0x5d, 0x42, 0x1f, 0x00, 0x21, 0x3e, 0x9b, 0x84, 0xa5, 0xba, 0xe7, 0xf8, 0xd9, 0xc6,
    0x92, 0x8d, 0xac, 0xb3, 0xee, 0xf1, 0xd0, 0xcf, 0x6a, 0x75, 0x54, 0x4b, 0x16, 0x09, 0x28, 0x37,
    0x80, 0x9f, 0xbe, 0xa1, 0xfc, 0xe3, 0xc2, 0xdd, 0x78, 0x67, 0x46, 0x59, 0x04, 0x1b, 0x3a, 0x25,
    0x71, 0x6e, 0x4f, 0x50, 0x0d, 0x12, 0x33, 0x2c, 0x89, 0x96, 0xb7, 0xa8, 0xf5, 0xea, 0xcb, 0xd4,
    0xa4, 0xbb, 0x9a, 0x85, 0xd8, 0xc7, 0xe6, 0xf9, 0x5c, 0x43, 0x62, 0x7d, 0x20, 0x3f, 0x1e, 0x01,
    0x55, 0x4a, 0x6b, 0x74, 0x29, 0x36, 0x17, 0x08, 0xad, 0xb2, 0x93, 0x8c, 0xd1, 0xce, 0xef, 0xf0,
    0x47, 0x58, 0x79, 0x66, 0x3b, 0x24, 0x05, 0x1a, 0xbf, 0xa0, 0x81, 0x9e, 0xc3, 0xdc, 0xfd, 0xe2,
    0xb6, 0xa9, 0x88, 0x97, 0xca, 0xd5, 0xf4, 0xeb, 0x4e, 0x51, 0x70, 0x6f, 0x32, 0x2d, 0x0c, 0x13,
    0xec, 0xf3, 0xd2, 0xcd, 0x90, 0x8f, 0xae, 0xb1, 0x14, 0x0b, 0x2a, 0x35, 0x68, 0x77, 0x56, 0x49,
    0x1d, 0x02, 0x23, 0x3c, 0x61, 0x7e, 0x5f, 0x40, 0xe5, 0xfa, 0xdb, 0xc4, 0x99, 0x86, 0xa7, 0xb8,
    0x0f, 0x10, 0x31, 0x2e, 0x73, 0x6c, 0x4d, 0x52, 0xf7, 0xe8, 0xc9, 0xd6, 0x8b, 0x94, 0xb5, 0xaa,
    0xfe, 0xe1, 0xc0, 0xdf, 0x82, 0x9d, 0xbc, 0xa3, 0x06, 0x19, 0x38, 0x27, 0x7a, 0x65, 0x44, 0x5b,
    0x2b, 0x34, 0x15, 0x0a, 0x57, 0x48, 0x69, 0x76, 0xd3, 0xcc, 0xed, 0xf2, 0xaf, 0xb0, 0x91, 0x8e,
    0xda, 0xc5, 0xe4, 0xfb, 0xa6, 0xb9, 0x98, 0x87, 0x22, 0x3d, 0x1c, 0x03, 0x5e, 0x41, 0x60, 0x7f,
    0xc8, 0xd7, 0xf6, 0xe9, 0xb4, 0xab, 0x8a, 0x95, 0x30, 0x2f, 0x0e, 0x11, 0x4c, 0x53, 0x72, 0x6d,
    0x39, 0x26, 0x07, 0x18, 0x45, 0x5a, 0x7b, 0x64, 0xc1, 0xde, 0xff, 0xe0, 0xbd, 0xa2, 0x83, 0x9c,
};
#define AES_AFFINE(X) do { X = aes_affine[X]; } while(0)
#else
#define AES_AFFINE(X) do {                              \
    uint8_t $t;                                         \
    $t = X;  $t = ( ( $t << 1 ) | ( $t >> 7 ) ) & 0xFF; \
    X ^= $t; $t = ( ( $t << 1 ) | ( $t >> 7 ) ) & 0xFF; \
    X ^= $t; $t = ( ( $t << 1 ) | ( $t >> 7 ) ) & 0xFF; \
    X ^= $t; $t = ( ( $t << 1 ) | ( $t >> 7 ) ) & 0xFF; \
    X ^= $t ^ 0x63;                                     \
} while ( 0 )
#endif


/*
 * Random bytes:
 * (4x MASKED_SEC_MULT)
 * 2*(MBEDTLS_AES_NTH_ORD_MASK_ORDER*(MBEDTLS_AES_NTH_ORD_MASK_ORDER-1))
 * + 2*(MBEDTLS_AES_NTH_ORD_MASK_ORDER-1)
 * So max MBEDTLS_AES_NTH_ORD_MASK_ORDER is 5 with the ChaCha-based LQRNG
 */
#define MASKED_EXP254_RANDBYTES (4*MASKED_SEC_MULT_RANDBYTES + 2*(MBEDTLS_AES_NTH_ORD_MASK_ORDER-1))
#define MASKED_EXP254(Ys,Xs,RB) do {                                            \
    uint8_t $z[MBEDTLS_AES_NTH_ORD_MASK_ORDER],                                 \
            $w[MBEDTLS_AES_NTH_ORD_MASK_ORDER],                                 \
            $t1, $t2;                                                           \
    int $x;                                                                     \
    /* zi = Xi^2, z = X^2 */                                                    \
    $t1 = 0;                                                                    \
    UNROLL_LOOP for( $x = 0; $x<MBEDTLS_AES_NTH_ORD_MASK_ORDER-1; ++$x ){       \
        $t2 = *(RB)++;                                                          \
        $z[$x] = gf256_sqr_lu[Xs[$x]] ^ $t1 ^ $t2;                              \
        $t1 = $t2;                                                              \
    }                                                                           \
    $z[$x] = gf256_sqr_lu[Xs[$x]] ^ $t1;                                        \
    /* Yi = Xi*zi, Y = X^3 */                                                   \
    MASKED_SEC_MULT(Ys,$z,Xs,RB);                                               \
    /* wi = Yi^4, w = X^12 */                                                   \
    $t1 = 0;                                                                    \
    UNROLL_LOOP for( $x = 0; $x<MBEDTLS_AES_NTH_ORD_MASK_ORDER-1; ++$x ){       \
        $t2 = *(RB)++;                                                          \
        $w[$x] = gf256_sqr_lu[gf256_sqr_lu[Ys[$x]]] ^ $t1 ^ $t2;                \
        $t1 = $t2;                                                              \
    }                                                                           \
    $w[$x] = gf256_sqr_lu[gf256_sqr_lu[Ys[$x]]] ^ $t1;                          \
    /* Yi = Yi*wi, Y = X^15 */                                                  \
    MASKED_SEC_MULT(Ys,Ys,$w,RB);                                               \
    /* Yi = Yi^16, Y = X^240 */                                                 \
    UNROLL_LOOP for( $x = 0; $x<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++$x ){         \
        Ys[$x] = gf256_sqr_lu[gf256_sqr_lu[gf256_sqr_lu[gf256_sqr_lu[Ys[$x]]]]];\
    }                                                                           \
    /* Yi = Yi*wi, Y = X^252 */                                                 \
    MASKED_SEC_MULT(Ys,Ys,$w,RB);                                               \
    /* Yi = Yi*zi, Y = X^254 */                                                 \
    MASKED_SEC_MULT(Ys,Ys,$z,RB);                                               \
} while ( 0 )

#if (LQRNG_GETBUF_MAX_SIZE < MASKED_EXP254_RANDBYTES)
#error  MASKED_EXP254_RANDBYTES is greater than LQRNG_GETBUF_MAX_SIZE, this is currently not supported.
#endif

static void _masked_sbox_impl(const uint8_t rbs[MASKED_EXP254_RANDBYTES],
                              uint8_t out[MBEDTLS_AES_NTH_ORD_MASK_ORDER],
                              const uint8_t in[MBEDTLS_AES_NTH_ORD_MASK_ORDER])
{
    int x;
    const uint8_t *RB = rbs;
    MASKED_EXP254(out, in, RB);
    UNROLL_LOOP for( x = 0; x<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++x ){
        AES_AFFINE(out[x]);
    }
    if(!(MBEDTLS_AES_NTH_ORD_MASK_ORDER & 1)) { out[0] ^= 0x63; }
}

#define MASKED_SBOX(Ys,Xs) do {                                             \
    _masked_sbox_impl(lqrng_getbuf(LQRNG,MASKED_EXP254_RANDBYTES),Ys,Xs);   \
} while ( 0 )


#define MC \
    V(00,00,00,00), V(03,01,01,02), V(06,02,02,04), V(05,03,03,06), \
    V(0c,04,04,08), V(0f,05,05,0a), V(0a,06,06,0c), V(09,07,07,0e), \
    V(18,08,08,10), V(1b,09,09,12), V(1e,0a,0a,14), V(1d,0b,0b,16), \
    V(14,0c,0c,18), V(17,0d,0d,1a), V(12,0e,0e,1c), V(11,0f,0f,1e), \
    V(30,10,10,20), V(33,11,11,22), V(36,12,12,24), V(35,13,13,26), \
    V(3c,14,14,28), V(3f,15,15,2a), V(3a,16,16,2c), V(39,17,17,2e), \
    V(28,18,18,30), V(2b,19,19,32), V(2e,1a,1a,34), V(2d,1b,1b,36), \
    V(24,1c,1c,38), V(27,1d,1d,3a), V(22,1e,1e,3c), V(21,1f,1f,3e), \
    V(60,20,20,40), V(63,21,21,42), V(66,22,22,44), V(65,23,23,46), \
    V(6c,24,24,48), V(6f,25,25,4a), V(6a,26,26,4c), V(69,27,27,4e), \
    V(78,28,28,50), V(7b,29,29,52), V(7e,2a,2a,54), V(7d,2b,2b,56), \
    V(74,2c,2c,58), V(77,2d,2d,5a), V(72,2e,2e,5c), V(71,2f,2f,5e), \
    V(50,30,30,60), V(53,31,31,62), V(56,32,32,64), V(55,33,33,66), \
    V(5c,34,34,68), V(5f,35,35,6a), V(5a,36,36,6c), V(59,37,37,6e), \
    V(48,38,38,70), V(4b,39,39,72), V(4e,3a,3a,74), V(4d,3b,3b,76), \
    V(44,3c,3c,78), V(47,3d,3d,7a), V(42,3e,3e,7c), V(41,3f,3f,7e), \
    V(c0,40,40,80), V(c3,41,41,82), V(c6,42,42,84), V(c5,43,43,86), \
    V(cc,44,44,88), V(cf,45,45,8a), V(ca,46,46,8c), V(c9,47,47,8e), \
    V(d8,48,48,90), V(db,49,49,92), V(de,4a,4a,94), V(dd,4b,4b,96), \
    V(d4,4c,4c,98), V(d7,4d,4d,9a), V(d2,4e,4e,9c), V(d1,4f,4f,9e), \
    V(f0,50,50,a0), V(f3,51,51,a2), V(f6,52,52,a4), V(f5,53,53,a6), \
    V(fc,54,54,a8), V(ff,55,55,aa), V(fa,56,56,ac), V(f9,57,57,ae), \
    V(e8,58,58,b0), V(eb,59,59,b2), V(ee,5a,5a,b4), V(ed,5b,5b,b6), \
    V(e4,5c,5c,b8), V(e7,5d,5d,ba), V(e2,5e,5e,bc), V(e1,5f,5f,be), \
    V(a0,60,60,c0), V(a3,61,61,c2), V(a6,62,62,c4), V(a5,63,63,c6), \
    V(ac,64,64,c8), V(af,65,65,ca), V(aa,66,66,cc), V(a9,67,67,ce), \
    V(b8,68,68,d0), V(bb,69,69,d2), V(be,6a,6a,d4), V(bd,6b,6b,d6), \
    V(b4,6c,6c,d8), V(b7,6d,6d,da), V(b2,6e,6e,dc), V(b1,6f,6f,de), \
    V(90,70,70,e0), V(93,71,71,e2), V(96,72,72,e4), V(95,73,73,e6), \
    V(9c,74,74,e8), V(9f,75,75,ea), V(9a,76,76,ec), V(99,77,77,ee), \
    V(88,78,78,f0), V(8b,79,79,f2), V(8e,7a,7a,f4), V(8d,7b,7b,f6), \
    V(84,7c,7c,f8), V(87,7d,7d,fa), V(82,7e,7e,fc), V(81,7f,7f,fe), \
    V(9b,80,80,1b), V(98,81,81,19), V(9d,82,82,1f), V(9e,83,83,1d), \
    V(97,84,84,13), V(94,85,85,11), V(91,86,86,17), V(92,87,87,15), \
    V(83,88,88,0b), V(80,89,89,09), V(85,8a,8a,0f), V(86,8b,8b,0d), \
    V(8f,8c,8c,03), V(8c,8d,8d,01), V(89,8e,8e,07), V(8a,8f,8f,05), \
    V(ab,90,90,3b), V(a8,91,91,39), V(ad,92,92,3f), V(ae,93,93,3d), \
    V(a7,94,94,33), V(a4,95,95,31), V(a1,96,96,37), V(a2,97,97,35), \
    V(b3,98,98,2b), V(b0,99,99,29), V(b5,9a,9a,2f), V(b6,9b,9b,2d), \
    V(bf,9c,9c,23), V(bc,9d,9d,21), V(b9,9e,9e,27), V(ba,9f,9f,25), \
    V(fb,a0,a0,5b), V(f8,a1,a1,59), V(fd,a2,a2,5f), V(fe,a3,a3,5d), \
    V(f7,a4,a4,53), V(f4,a5,a5,51), V(f1,a6,a6,57), V(f2,a7,a7,55), \
    V(e3,a8,a8,4b), V(e0,a9,a9,49), V(e5,aa,aa,4f), V(e6,ab,ab,4d), \
    V(ef,ac,ac,43), V(ec,ad,ad,41), V(e9,ae,ae,47), V(ea,af,af,45), \
    V(cb,b0,b0,7b), V(c8,b1,b1,79), V(cd,b2,b2,7f), V(ce,b3,b3,7d), \
    V(c7,b4,b4,73), V(c4,b5,b5,71), V(c1,b6,b6,77), V(c2,b7,b7,75), \
    V(d3,b8,b8,6b), V(d0,b9,b9,69), V(d5,ba,ba,6f), V(d6,bb,bb,6d), \
    V(df,bc,bc,63), V(dc,bd,bd,61), V(d9,be,be,67), V(da,bf,bf,65), \
    V(5b,c0,c0,9b), V(58,c1,c1,99), V(5d,c2,c2,9f), V(5e,c3,c3,9d), \
    V(57,c4,c4,93), V(54,c5,c5,91), V(51,c6,c6,97), V(52,c7,c7,95), \
    V(43,c8,c8,8b), V(40,c9,c9,89), V(45,ca,ca,8f), V(46,cb,cb,8d), \
    V(4f,cc,cc,83), V(4c,cd,cd,81), V(49,ce,ce,87), V(4a,cf,cf,85), \
    V(6b,d0,d0,bb), V(68,d1,d1,b9), V(6d,d2,d2,bf), V(6e,d3,d3,bd), \
    V(67,d4,d4,b3), V(64,d5,d5,b1), V(61,d6,d6,b7), V(62,d7,d7,b5), \
    V(73,d8,d8,ab), V(70,d9,d9,a9), V(75,da,da,af), V(76,db,db,ad), \
    V(7f,dc,dc,a3), V(7c,dd,dd,a1), V(79,de,de,a7), V(7a,df,df,a5), \
    V(3b,e0,e0,db), V(38,e1,e1,d9), V(3d,e2,e2,df), V(3e,e3,e3,dd), \
    V(37,e4,e4,d3), V(34,e5,e5,d1), V(31,e6,e6,d7), V(32,e7,e7,d5), \
    V(23,e8,e8,cb), V(20,e9,e9,c9), V(25,ea,ea,cf), V(26,eb,eb,cd), \
    V(2f,ec,ec,c3), V(2c,ed,ed,c1), V(29,ee,ee,c7), V(2a,ef,ef,c5), \
    V(0b,f0,f0,fb), V(08,f1,f1,f9), V(0d,f2,f2,ff), V(0e,f3,f3,fd), \
    V(07,f4,f4,f3), V(04,f5,f5,f1), V(01,f6,f6,f7), V(02,f7,f7,f5), \
    V(13,f8,f8,eb), V(10,f9,f9,e9), V(15,fa,fa,ef), V(16,fb,fb,ed), \
    V(1f,fc,fc,e3), V(1c,fd,fd,e1), V(19,fe,fe,e7), V(1a,ff,ff,e5)

#define V(a,b,c,d) 0x##a##b##c##d
static const uint32_t MC0[256] = { MC };
#undef V

#if !defined(MBEDTLS_AES_FEWER_TABLES)

#define V(a,b,c,d) 0x##b##c##d##a
static const uint32_t MC1[256] = { MC };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const uint32_t MC2[256] = { MC };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const uint32_t MC3[256] = { MC };
#undef V

#endif /* !MBEDTLS_AES_FEWER_TABLES */

#undef MC

#if defined(MBEDTLS_AES_FEWER_TABLES)

#define AES_MC0(idx) MC0[idx]
#define AES_MC1(idx) ROTL8(  MC0[idx] )
#define AES_MC2(idx) ROTL16( MC0[idx] )
#define AES_MC3(idx) ROTL24( MC0[idx] )

#else /* MBEDTLS_AES_FEWER_TABLES */

#define AES_MC0(idx) MC0[idx]
#define AES_MC1(idx) MC1[idx]
#define AES_MC2(idx) MC2[idx]
#define AES_MC3(idx) MC3[idx]

#endif /* MBEDTLS_AES_FEWER_TABLES */

#define AES_MASKED_FTx(x,Xs,Ys,i) do {                                  \
    int $x;                                                             \
    uint8_t $sb[MBEDTLS_AES_NTH_ORD_MASK_ORDER],                        \
            $yv[MBEDTLS_AES_NTH_ORD_MASK_ORDER];                        \
    UNROLL_LOOP for( $x = 0; $x<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++$x ){ \
        $yv[$x] = ((Ys[$x]) >> ((i)*8)) & 0xFF;                         \
    }                                                                   \
    MASKED_SBOX($sb, $yv);                                              \
    UNROLL_LOOP for( $x = 0; $x<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++$x ){ \
        /* Xs[$x] ^= AES_FT##x(RSb[$sb[$x]]); */                        \
        Xs[$x] ^= AES_MC##x($sb[$x]);                                   \
    }                                                                   \
} while ( 0 )

#define AES_MASKED_FSUBROUND(Xs,RK,mRKs,Y0s,Y1s,Y2s,Y3s)                    \
    do {                                                                    \
        int $x;                                                             \
        Xs[0] = *RK++;                                                      \
        UNROLL_LOOP for( $x = 1; $x<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++$x ){ \
            Xs[$x] = *mRKs[$x-1]++;                                         \
        }                                                                   \
        AES_MASKED_FTx(0, Xs,Y0s,0);                                        \
        AES_MASKED_FTx(1, Xs,Y1s,1);                                        \
        AES_MASKED_FTx(2, Xs,Y2s,2);                                        \
        AES_MASKED_FTx(3, Xs,Y3s,3);                                        \
    } while ( 0 )

#define AES_MASKED_FROUND(Xss, Yss, RK, mRKs)               \
    do {                                                    \
        AES_MASKED_FSUBROUND(Xss[0],RK,mRKs,                \
                             Yss[0],Yss[1],Yss[2],Yss[3]);  \
        AES_MASKED_FSUBROUND(Xss[1],RK,mRKs,                \
                             Yss[1],Yss[2],Yss[3],Yss[0]);  \
        AES_MASKED_FSUBROUND(Xss[2],RK,mRKs,                \
                             Yss[2],Yss[3],Yss[0],Yss[1]);  \
        AES_MASKED_FSUBROUND(Xss[3],RK,mRKs,                \
                             Yss[3],Yss[0],Yss[1],Yss[2]);  \
    } while ( 0 )

#define AES_MASKED_FINAL_FSb(Xs,Ys,i) do {                              \
    int $x;                                                             \
    uint8_t $sb[MBEDTLS_AES_NTH_ORD_MASK_ORDER],                        \
            $yv[MBEDTLS_AES_NTH_ORD_MASK_ORDER];                        \
    UNROLL_LOOP for( $x = 0; $x<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++$x ){ \
        $yv[$x] = ((Ys[$x]) >> ((i)*8)) & 0xFF;                         \
    }                                                                   \
    MASKED_SBOX($sb, $yv);                                              \
    UNROLL_LOOP for( $x = 0; $x<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++$x ){ \
        (Xs[$x]) ^= (uint32_t)($sb[$x]) << ((i)*8);                     \
    }                                                                   \
} while ( 0 )

#define AES_MASKED_FINAL_FSUBROUND(Xs,RK,mRKs,Y0s,Y1s,Y2s,Y3s )             \
    do {                                                                    \
        int $x;                                                             \
        Xs[0] = *RK++;                                                      \
        UNROLL_LOOP for( $x = 1; $x<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++$x ){ \
            Xs[$x] = *mRKs[$x-1]++;                                         \
        }                                                                   \
        AES_MASKED_FINAL_FSb(Xs,Y0s,0);                                     \
        AES_MASKED_FINAL_FSb(Xs,Y1s,1);                                     \
        AES_MASKED_FINAL_FSb(Xs,Y2s,2);                                     \
        AES_MASKED_FINAL_FSb(Xs,Y3s,3);                                     \
    } while ( 0 )

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                     \
    do                                                          \
    {                                                           \
        (X0) = *RK++ ^ AES_FT0( ( (Y0)       ) & 0xFF ) ^       \
                       AES_FT1( ( (Y1) >>  8 ) & 0xFF ) ^       \
                       AES_FT2( ( (Y2) >> 16 ) & 0xFF ) ^       \
                       AES_FT3( ( (Y3) >> 24 ) & 0xFF );        \
                                                                \
        (X1) = *RK++ ^ AES_FT0( ( (Y1)       ) & 0xFF ) ^       \
                       AES_FT1( ( (Y2) >>  8 ) & 0xFF ) ^       \
                       AES_FT2( ( (Y3) >> 16 ) & 0xFF ) ^       \
                       AES_FT3( ( (Y0) >> 24 ) & 0xFF );        \
                                                                \
        (X2) = *RK++ ^ AES_FT0( ( (Y2)       ) & 0xFF ) ^       \
                       AES_FT1( ( (Y3) >>  8 ) & 0xFF ) ^       \
                       AES_FT2( ( (Y0) >> 16 ) & 0xFF ) ^       \
                       AES_FT3( ( (Y1) >> 24 ) & 0xFF );        \
                                                                \
        (X3) = *RK++ ^ AES_FT0( ( (Y3)       ) & 0xFF ) ^       \
                       AES_FT1( ( (Y0) >>  8 ) & 0xFF ) ^       \
                       AES_FT2( ( (Y1) >> 16 ) & 0xFF ) ^       \
                       AES_FT3( ( (Y2) >> 24 ) & 0xFF );        \
    } while( 0 )

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                 \
    do                                                      \
    {                                                       \
        (X0) = *RK++ ^ AES_RT0( ( (Y0)       ) & 0xFF ) ^   \
                       AES_RT1( ( (Y3) >>  8 ) & 0xFF ) ^   \
                       AES_RT2( ( (Y2) >> 16 ) & 0xFF ) ^   \
                       AES_RT3( ( (Y1) >> 24 ) & 0xFF );    \
                                                            \
        (X1) = *RK++ ^ AES_RT0( ( (Y1)       ) & 0xFF ) ^   \
                       AES_RT1( ( (Y0) >>  8 ) & 0xFF ) ^   \
                       AES_RT2( ( (Y3) >> 16 ) & 0xFF ) ^   \
                       AES_RT3( ( (Y2) >> 24 ) & 0xFF );    \
                                                            \
        (X2) = *RK++ ^ AES_RT0( ( (Y2)       ) & 0xFF ) ^   \
                       AES_RT1( ( (Y1) >>  8 ) & 0xFF ) ^   \
                       AES_RT2( ( (Y0) >> 16 ) & 0xFF ) ^   \
                       AES_RT3( ( (Y3) >> 24 ) & 0xFF );    \
                                                            \
        (X3) = *RK++ ^ AES_RT0( ( (Y3)       ) & 0xFF ) ^   \
                       AES_RT1( ( (Y2) >>  8 ) & 0xFF ) ^   \
                       AES_RT2( ( (Y1) >> 16 ) & 0xFF ) ^   \
                       AES_RT3( ( (Y0) >> 24 ) & 0xFF );    \
    } while( 0 )

uint64_t aes_timing_table[32];

/*
 * AES-ECB block encryption
 */
#if !defined(MBEDTLS_AES_ENCRYPT_ALT)
int mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    int i;
    uint32_t *RK = ctx->rk;
    #ifdef MBEDTLS_AES_NTH_ORD_MASK
    int j, k;
    uint32_t tmp0, tmp1;
    struct
    {
        uint32_t X[4][MBEDTLS_AES_NTH_ORD_MASK_ORDER];
        uint32_t Y[4][MBEDTLS_AES_NTH_ORD_MASK_ORDER];
    } t;
    lqrng_state sLQRNG, *LQRNG = &sLQRNG;

    memset(aes_timing_table, 0, sizeof(aes_timing_table));
    uint64_t* tt = aes_timing_table;
    #define NEXT_TS()  { *(tt++) = __rdtsc(); }
    NEXT_TS();

    lqrng_init(LQRNG, (uint32_t)__rdtsc());
    
    NEXT_TS();

    // TODO: mRK should be part of regular key schedule
    #if (MBEDTLS_AES_NTH_ORD_MASK_ROUNDS > 0)
    uint32_t mRK[MBEDTLS_AES_NTH_ORD_MASK_ROUNDS * 4 * MBEDTLS_AES_NTH_ORD_MASK_ORDER], *mRKs[MBEDTLS_AES_NTH_ORD_MASK_ORDER-1];
    UNROLL_LOOP for( k = 0; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER-1; ++k ){
        mRKs[k] = &mRK[MBEDTLS_AES_NTH_ORD_MASK_ROUNDS * 4 * k];
    }
    #else /* MBEDTLS_AES_NTH_ORD_MASK_ROUNDS > 0 */
    /* 14 is max nr, 15 is max nr + 1 */
    uint32_t mRK[15 * 4 * MBEDTLS_AES_NTH_ORD_MASK_ORDER], *mRKs[MBEDTLS_AES_NTH_ORD_MASK_ORDER-1];
    UNROLL_LOOP for( k = 0; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER-1; ++k ){
        mRKs[k] = &mRK[(ctx->nr+1) * 4 * k];
    }
    #endif

    UNROLL_LOOP for( i=0; i<4; ++i)
    {
        // once mRK is part of key schedule, use mRK shares instead
        #if (MBEDTLS_AES_NTH_ORD_MASK_ROUNDS > 0)
        UNROLL_LOOP for( j=0; j<MBEDTLS_AES_NTH_ORD_MASK_ROUNDS; ++j)
        #else /* MBEDTLS_AES_NTH_ORD_MASK_ROUNDS > 0 */
        for( j=0; j<(ctx->nr+1); ++j)
        #endif /* MBEDTLS_AES_NTH_ORD_MASK_ROUNDS > 0 */
        {
            tmp0 = 0;
            UNROLL_LOOP for( k = 0; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER-1; ++k ){
                tmp1 = lqrng_get32(LQRNG);
                mRKs[k][i+4*j] = tmp0 ^ tmp1;
                tmp0 = tmp1;
            }
            RK[4*(j+1)] ^= tmp0;
        }

        tmp0 = *(RK++);
        UNROLL_LOOP for( k = 1; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++k ){
            tmp1 = lqrng_get32(LQRNG);
            t.X[i][k] = tmp0 ^ tmp1;
            tmp0 = tmp1;
        }
        GET_UINT32_LE( t.X[i][0], input,  4*i ); 
        t.X[i][0] ^= tmp0;
    }

    NEXT_TS();

    #if (MBEDTLS_AES_NTH_ORD_MASK_ROUNDS == 0)
    /* Case 0: all rounds are masked */
    AES_MASKED_FROUND(t.Y, t.X, RK, mRKs);
    NEXT_TS();
    for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
    {
        AES_MASKED_FROUND(t.X, t.Y, RK, mRKs);
        NEXT_TS();
        AES_MASKED_FROUND(t.Y, t.X, RK, mRKs);
        NEXT_TS();
    }
    #elif (MBEDTLS_AES_NTH_ORD_MASK_ROUNDS & 1)
    /* Case 2n+1: odd number of rounds at the beginning and end */
    AES_MASKED_FROUND(t.Y, t.X, RK, mRKs);
    NEXT_TS();
    for( i = ( (MBEDTLS_AES_NTH_ORD_MASK_ROUNDS - 1) >> 1 ); i > 0; i-- )
    {
        AES_MASKED_FROUND(t.X, t.Y, RK, mRKs);
        NEXT_TS();
        AES_MASKED_FROUND(t.Y, t.X, RK, mRKs);
        NEXT_TS();
    }
    // Unmasked roudns
    UNROLL_LOOP for(i=0;i<4;++i) {
        UNROLL_LOOP for( k = 1; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++k ){
            t.Y[i][0] ^= t.Y[i][k];
        }
    }
    for( i = ( ctx->nr >> 1 ) - MBEDTLS_AES_NTH_ORD_MASK_ROUNDS; i > 0; i-- )
    {
        AES_FROUND( t.X[0][0], t.X[1][0], t.X[2][0], t.X[3][0], t.Y[0][0], t.Y[1][0], t.Y[2][0], t.Y[3][0] );
        AES_FROUND( t.Y[0][0], t.Y[1][0], t.Y[2][0], t.Y[3][0], t.X[0][0], t.X[1][0], t.X[2][0], t.X[3][0] );
    }
    // Remask key and state
    NEXT_TS();
    UNROLL_LOOP for( k = 0; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER-1; ++k ){
        mRKs[k] = &mRK[MBEDTLS_AES_NTH_ORD_MASK_ROUNDS * 4 * k];
    }
    UNROLL_LOOP for( i=0; i<4; ++i)
    {
        // once mRK is part of key schedule, use mRK shares instead
        UNROLL_LOOP for( j=0; j<MBEDTLS_AES_NTH_ORD_MASK_ROUNDS; ++j)
        {
            tmp0 = 0;
            UNROLL_LOOP for( k = 0; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER-1; ++k ){
                tmp1 = lqrng_get32(LQRNG);
                mRKs[k][i+4*j] = tmp0 ^ tmp1;
                tmp0 = tmp1;
            }
            RK[i+4*j] ^= tmp0;
        }

        tmp0 = 0;
        UNROLL_LOOP for( k = 1; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++k ){
            tmp1 = lqrng_get32(LQRNG);
            t.Y[i][k] = tmp0 ^ tmp1;
            tmp0 = tmp1;
        }
        t.Y[i][0] ^= tmp0;
    }
    NEXT_TS();
    for( i = ( (MBEDTLS_AES_NTH_ORD_MASK_ROUNDS - 1) >> 1 ); i > 0; i-- )
    {
        AES_MASKED_FROUND(t.X, t.Y, RK, mRKs);
        NEXT_TS();
        AES_MASKED_FROUND(t.Y, t.X, RK, mRKs);
        NEXT_TS();
    }
    #else /* (MBEDTLS_AES_NTH_ORD_MASK_ROUNDS & 1) */
    /* Case 2n: even number of rounds at the beginning and end */
    for( i = ( MBEDTLS_AES_NTH_ORD_MASK_ROUNDS >> 1 ); i > 0; i-- )
    {
        AES_MASKED_FROUND(t.Y, t.X, RK, mRKs);
        NEXT_TS();
        AES_MASKED_FROUND(t.X, t.Y, RK, mRKs);
        NEXT_TS();
    }
    // Unmasked roudns
    UNROLL_LOOP for(i=0;i<4;++i) {
        UNROLL_LOOP for( k = 1; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++k ){
            t.X[i][0] ^= t.X[i][k];
        }
    }
    for( i = ( ctx->nr >> 1 ) - MBEDTLS_AES_NTH_ORD_MASK_ROUNDS; i > 0; i-- )
    {
        AES_FROUND( t.Y[0][0], t.Y[1][0], t.Y[2][0], t.Y[3][0], t.X[0][0], t.X[1][0], t.X[2][0], t.X[3][0] );
        AES_FROUND( t.X[0][0], t.X[1][0], t.X[2][0], t.X[3][0], t.Y[0][0], t.Y[1][0], t.Y[2][0], t.Y[3][0] );
    }
    // Remask key and state
    NEXT_TS();
    UNROLL_LOOP for( k = 0; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER-1; ++k ){
        mRKs[k] = &mRK[MBEDTLS_AES_NTH_ORD_MASK_ROUNDS * 4 * k];
    }
    UNROLL_LOOP for( i=0; i<4; ++i)
    {
        // once mRK is part of key schedule, use mRK shares instead
        UNROLL_LOOP for( j=0; j<MBEDTLS_AES_NTH_ORD_MASK_ROUNDS; ++j)
        {
            tmp0 = 0;
            UNROLL_LOOP for( k = 0; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER-1; ++k ){
                tmp1 = lqrng_get32(LQRNG);
                mRKs[k][i+4*j] = tmp0 ^ tmp1;
                tmp0 = tmp1;
            }
            RK[i+4*j] ^= tmp0;
        }

        tmp0 = 0;
        UNROLL_LOOP for( k = 1; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++k ){
            tmp1 = lqrng_get32(LQRNG);
            t.X[i][k] = tmp0 ^ tmp1;
            tmp0 = tmp1;
        }
        t.X[i][0] ^= tmp0;
    }
    NEXT_TS();
    for( i = ( (MBEDTLS_AES_NTH_ORD_MASK_ROUNDS-2) >> 1 ); i > 0; i-- )
    {
        AES_MASKED_FROUND(t.Y, t.X, RK, mRKs);
        NEXT_TS();
        AES_MASKED_FROUND(t.X, t.Y, RK, mRKs);
        NEXT_TS();
    }
    AES_MASKED_FROUND(t.Y, t.X, RK, mRKs);
    NEXT_TS();
    #endif /* (MBEDTLS_AES_NTH_ORD_MASK_ROUNDS & 1) */

    AES_MASKED_FINAL_FSUBROUND(t.X[0], RK, mRKs, t.Y[0], t.Y[1], t.Y[2], t.Y[3]);
    AES_MASKED_FINAL_FSUBROUND(t.X[1], RK, mRKs, t.Y[1], t.Y[2], t.Y[3], t.Y[0]);
    AES_MASKED_FINAL_FSUBROUND(t.X[2], RK, mRKs, t.Y[2], t.Y[3], t.Y[0], t.Y[1]);
    AES_MASKED_FINAL_FSUBROUND(t.X[3], RK, mRKs, t.Y[3], t.Y[0], t.Y[1], t.Y[2]);

    NEXT_TS();

    /* Unmask output */
    UNROLL_LOOP for(i=0;i<4;++i) {
        UNROLL_LOOP for( k = 1; k<MBEDTLS_AES_NTH_ORD_MASK_ORDER; ++k ){
            t.X[i][0] ^= t.X[i][k];
        }
    }

    NEXT_TS();
    
    PUT_UINT32_LE( t.X[0][0], output,  0 );
    PUT_UINT32_LE( t.X[1][0], output,  4 );
    PUT_UINT32_LE( t.X[2][0], output,  8 );
    PUT_UINT32_LE( t.X[3][0], output, 12 );
    
    NEXT_TS();
    #undef NEXT_TS

    mbedtls_platform_zeroize( &mRK, sizeof( mRK ) );
    #else /* MBEDTLS_AES_NTH_ORD_MASK */
    struct
    {
        uint32_t X[4];
        uint32_t Y[4];
    } t;
    GET_UINT32_LE( t.X[0], input,  0 ); t.X[0] ^= *RK++;
    GET_UINT32_LE( t.X[1], input,  4 ); t.X[1] ^= *RK++;
    GET_UINT32_LE( t.X[2], input,  8 ); t.X[2] ^= *RK++;
    GET_UINT32_LE( t.X[3], input, 12 ); t.X[3] ^= *RK++;
    
    for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
    {
        // printf("%08x %08x %08x %08x\n", t.X[0], t.X[1], t.X[2], t.X[3]);
        AES_FROUND( t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3] );
        AES_FROUND( t.X[0], t.X[1], t.X[2], t.X[3], t.Y[0], t.Y[1], t.Y[2], t.Y[3] );
    }

    // printf("%08x %08x %08x %08x\n", t.X[0], t.X[1], t.X[2], t.X[3]);
    AES_FROUND( t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3] );

    // printf("%08x %08x %08x %08x\n", t.Y[0], t.Y[1], t.Y[2], t.Y[3]);
    t.X[0] = *RK++ ^ \
            ( (uint32_t) FSb[ ( t.Y[0]       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( t.Y[1] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( t.Y[2] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( t.Y[3] >> 24 ) & 0xFF ] << 24 );

    t.X[1] = *RK++ ^ \
            ( (uint32_t) FSb[ ( t.Y[1]       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( t.Y[2] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( t.Y[3] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( t.Y[0] >> 24 ) & 0xFF ] << 24 );

    t.X[2] = *RK++ ^ \
            ( (uint32_t) FSb[ ( t.Y[2]       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( t.Y[3] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( t.Y[0] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( t.Y[1] >> 24 ) & 0xFF ] << 24 );

    t.X[3] = *RK++ ^ \
            ( (uint32_t) FSb[ ( t.Y[3]       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( t.Y[0] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( t.Y[1] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( t.Y[2] >> 24 ) & 0xFF ] << 24 );

    PUT_UINT32_LE( t.X[0], output,  0 );
    PUT_UINT32_LE( t.X[1], output,  4 );
    PUT_UINT32_LE( t.X[2], output,  8 );
    PUT_UINT32_LE( t.X[3], output, 12 );
    #endif /* MBEDTLS_AES_NTH_ORD_MASK */

    mbedtls_platform_zeroize( &t, sizeof( t ) );

    return( 0 );
}
#endif /* !MBEDTLS_AES_ENCRYPT_ALT */

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_aes_encrypt( mbedtls_aes_context *ctx,
                          const unsigned char input[16],
                          unsigned char output[16] )
{
    mbedtls_internal_aes_encrypt( ctx, input, output );
}
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

/*
 * AES-ECB block decryption
 */
#if !defined(MBEDTLS_AES_DECRYPT_ALT)
int mbedtls_internal_aes_decrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    int i;
    uint32_t *RK = ctx->rk;
    struct
    {
        uint32_t X[4];
        uint32_t Y[4];
    } t;

    GET_UINT32_LE( t.X[0], input,  0 ); t.X[0] ^= *RK++;
    GET_UINT32_LE( t.X[1], input,  4 ); t.X[1] ^= *RK++;
    GET_UINT32_LE( t.X[2], input,  8 ); t.X[2] ^= *RK++;
    GET_UINT32_LE( t.X[3], input, 12 ); t.X[3] ^= *RK++;

    for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
    {
        AES_RROUND( t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3] );
        AES_RROUND( t.X[0], t.X[1], t.X[2], t.X[3], t.Y[0], t.Y[1], t.Y[2], t.Y[3] );
    }

    AES_RROUND( t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3] );

    t.X[0] = *RK++ ^ \
            ( (uint32_t) RSb[ ( t.Y[0]       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( t.Y[3] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( t.Y[2] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( t.Y[1] >> 24 ) & 0xFF ] << 24 );

    t.X[1] = *RK++ ^ \
            ( (uint32_t) RSb[ ( t.Y[1]       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( t.Y[0] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( t.Y[3] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( t.Y[2] >> 24 ) & 0xFF ] << 24 );

    t.X[2] = *RK++ ^ \
            ( (uint32_t) RSb[ ( t.Y[2]       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( t.Y[1] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( t.Y[0] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( t.Y[3] >> 24 ) & 0xFF ] << 24 );

    t.X[3] = *RK++ ^ \
            ( (uint32_t) RSb[ ( t.Y[3]       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( t.Y[2] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( t.Y[1] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( t.Y[0] >> 24 ) & 0xFF ] << 24 );

    PUT_UINT32_LE( t.X[0], output,  0 );
    PUT_UINT32_LE( t.X[1], output,  4 );
    PUT_UINT32_LE( t.X[2], output,  8 );
    PUT_UINT32_LE( t.X[3], output, 12 );

    mbedtls_platform_zeroize( &t, sizeof( t ) );

    return( 0 );
}
#endif /* !MBEDTLS_AES_DECRYPT_ALT */

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_aes_decrypt( mbedtls_aes_context *ctx,
                          const unsigned char input[16],
                          unsigned char output[16] )
{
    mbedtls_internal_aes_decrypt( ctx, input, output );
}
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

/*
 * AES-ECB block encryption/decryption
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                           int mode,
                           const unsigned char input[16],
                           unsigned char output[16] )
{
    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_AES ) )
        return( mbedtls_aesni_crypt_ecb( ctx, mode, input, output ) );
#endif

#if defined(MBEDTLS_PADLOCK_C) && defined(MBEDTLS_HAVE_X86)
    if( aes_padlock_ace )
    {
        if( mbedtls_padlock_xcryptecb( ctx, mode, input, output ) == 0 )
            return( 0 );

        // If padlock data misaligned, we just fall back to
        // unaccelerated mode
        //
    }
#endif

    if( mode == MBEDTLS_AES_ENCRYPT )
        return( mbedtls_internal_aes_encrypt( ctx, input, output ) );
    else
        return( mbedtls_internal_aes_decrypt( ctx, input, output ) );
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * AES-CBC buffer encryption/decryption
 */
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[16];

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    if( length % 16 )
        return( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );

#if defined(MBEDTLS_PADLOCK_C) && defined(MBEDTLS_HAVE_X86)
    if( aes_padlock_ace )
    {
        if( mbedtls_padlock_xcryptcbc( ctx, mode, length, iv, input, output ) == 0 )
            return( 0 );

        // If padlock data misaligned, we just fall back to
        // unaccelerated mode
        //
    }
#endif

    if( mode == MBEDTLS_AES_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, 16 );
            mbedtls_aes_crypt_ecb( ctx, mode, input, output );

            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
    else
    {
        while( length > 0 )
        {
            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            mbedtls_aes_crypt_ecb( ctx, mode, output, output );
            memcpy( iv, output, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_XTS)

/* Endianess with 64 bits values */
#ifndef GET_UINT64_LE
#define GET_UINT64_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint64_t) (b)[(i) + 7] << 56 )             \
        | ( (uint64_t) (b)[(i) + 6] << 48 )             \
        | ( (uint64_t) (b)[(i) + 5] << 40 )             \
        | ( (uint64_t) (b)[(i) + 4] << 32 )             \
        | ( (uint64_t) (b)[(i) + 3] << 24 )             \
        | ( (uint64_t) (b)[(i) + 2] << 16 )             \
        | ( (uint64_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint64_t) (b)[(i)    ]       );            \
}
#endif

#ifndef PUT_UINT64_LE
#define PUT_UINT64_LE(n,b,i)                            \
{                                                       \
    (b)[(i) + 7] = (unsigned char) ( (n) >> 56 );       \
    (b)[(i) + 6] = (unsigned char) ( (n) >> 48 );       \
    (b)[(i) + 5] = (unsigned char) ( (n) >> 40 );       \
    (b)[(i) + 4] = (unsigned char) ( (n) >> 32 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
}
#endif

typedef unsigned char mbedtls_be128[16];

/*
 * GF(2^128) multiplication function
 *
 * This function multiplies a field element by x in the polynomial field
 * representation. It uses 64-bit word operations to gain speed but compensates
 * for machine endianess and hence works correctly on both big and little
 * endian machines.
 */
static void mbedtls_gf128mul_x_ble( unsigned char r[16],
                                    const unsigned char x[16] )
{
    uint64_t a, b, ra, rb;

    GET_UINT64_LE( a, x, 0 );
    GET_UINT64_LE( b, x, 8 );

    ra = ( a << 1 )  ^ 0x0087 >> ( 8 - ( ( b >> 63 ) << 3 ) );
    rb = ( a >> 63 ) | ( b << 1 );

    PUT_UINT64_LE( ra, r, 0 );
    PUT_UINT64_LE( rb, r, 8 );
}

/*
 * AES-XTS buffer encryption/decryption
 */
int mbedtls_aes_crypt_xts( mbedtls_aes_xts_context *ctx,
                           int mode,
                           size_t length,
                           const unsigned char data_unit[16],
                           const unsigned char *input,
                           unsigned char *output )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t blocks = length / 16;
    size_t leftover = length % 16;
    unsigned char tweak[16];
    unsigned char prev_tweak[16];
    unsigned char tmp[16];

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );
    AES_VALIDATE_RET( data_unit != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    /* Data units must be at least 16 bytes long. */
    if( length < 16 )
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;

    /* NIST SP 800-38E disallows data units larger than 2**20 blocks. */
    if( length > ( 1 << 20 ) * 16 )
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;

    /* Compute the tweak. */
    ret = mbedtls_aes_crypt_ecb( &ctx->tweak, MBEDTLS_AES_ENCRYPT,
                                 data_unit, tweak );
    if( ret != 0 )
        return( ret );

    while( blocks-- )
    {
        size_t i;

        if( leftover && ( mode == MBEDTLS_AES_DECRYPT ) && blocks == 0 )
        {
            /* We are on the last block in a decrypt operation that has
             * leftover bytes, so we need to use the next tweak for this block,
             * and this tweak for the lefover bytes. Save the current tweak for
             * the leftovers and then update the current tweak for use on this,
             * the last full block. */
            memcpy( prev_tweak, tweak, sizeof( tweak ) );
            mbedtls_gf128mul_x_ble( tweak, tweak );
        }

        for( i = 0; i < 16; i++ )
            tmp[i] = input[i] ^ tweak[i];

        ret = mbedtls_aes_crypt_ecb( &ctx->crypt, mode, tmp, tmp );
        if( ret != 0 )
            return( ret );

        for( i = 0; i < 16; i++ )
            output[i] = tmp[i] ^ tweak[i];

        /* Update the tweak for the next block. */
        mbedtls_gf128mul_x_ble( tweak, tweak );

        output += 16;
        input += 16;
    }

    if( leftover )
    {
        /* If we are on the leftover bytes in a decrypt operation, we need to
         * use the previous tweak for these bytes (as saved in prev_tweak). */
        unsigned char *t = mode == MBEDTLS_AES_DECRYPT ? prev_tweak : tweak;

        /* We are now on the final part of the data unit, which doesn't divide
         * evenly by 16. It's time for ciphertext stealing. */
        size_t i;
        unsigned char *prev_output = output - 16;

        /* Copy ciphertext bytes from the previous block to our output for each
         * byte of cyphertext we won't steal. At the same time, copy the
         * remainder of the input for this final round (since the loop bounds
         * are the same). */
        for( i = 0; i < leftover; i++ )
        {
            output[i] = prev_output[i];
            tmp[i] = input[i] ^ t[i];
        }

        /* Copy ciphertext bytes from the previous block for input in this
         * round. */
        for( ; i < 16; i++ )
            tmp[i] = prev_output[i] ^ t[i];

        ret = mbedtls_aes_crypt_ecb( &ctx->crypt, mode, tmp, tmp );
        if( ret != 0 )
            return ret;

        /* Write the result back to the previous block, overriding the previous
         * output we copied. */
        for( i = 0; i < 16; i++ )
            prev_output[i] = tmp[i] ^ t[i];
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/*
 * AES-CFB128 buffer encryption/decryption
 */
int mbedtls_aes_crypt_cfb128( mbedtls_aes_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c;
    size_t n;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );
    AES_VALIDATE_RET( iv_off != NULL );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    n = *iv_off;

    if( n > 15 )
        return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );

    if( mode == MBEDTLS_AES_DECRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char) c;

            n = ( n + 1 ) & 0x0F;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = ( n + 1 ) & 0x0F;
        }
    }

    *iv_off = n;

    return( 0 );
}

/*
 * AES-CFB8 buffer encryption/decryption
 */
int mbedtls_aes_crypt_cfb8( mbedtls_aes_context *ctx,
                            int mode,
                            size_t length,
                            unsigned char iv[16],
                            const unsigned char *input,
                            unsigned char *output )
{
    unsigned char c;
    unsigned char ov[17];

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );
    while( length-- )
    {
        memcpy( ov, iv, 16 );
        mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );

        if( mode == MBEDTLS_AES_DECRYPT )
            ov[16] = *input;

        c = *output++ = (unsigned char)( iv[0] ^ *input++ );

        if( mode == MBEDTLS_AES_ENCRYPT )
            ov[16] = c;

        memcpy( iv, ov + 1, 16 );
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
/*
 * AES-OFB (Output Feedback Mode) buffer encryption/decryption
 */
int mbedtls_aes_crypt_ofb( mbedtls_aes_context *ctx,
                           size_t length,
                           size_t *iv_off,
                           unsigned char iv[16],
                           const unsigned char *input,
                           unsigned char *output )
{
    int ret = 0;
    size_t n;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( iv_off != NULL );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    n = *iv_off;

    if( n > 15 )
        return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );

    while( length-- )
    {
        if( n == 0 )
        {
            ret = mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );
            if( ret != 0 )
                goto exit;
        }
        *output++ =  *input++ ^ iv[n];

        n = ( n + 1 ) & 0x0F;
    }

    *iv_off = n;

exit:
    return( ret );
}
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*
 * AES-CTR buffer encryption/decryption
 */
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c, i;
    size_t n;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( nc_off != NULL );
    AES_VALIDATE_RET( nonce_counter != NULL );
    AES_VALIDATE_RET( stream_block != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    n = *nc_off;

    if ( n > 0x0F )
        return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );

    while( length-- )
    {
        if( n == 0 ) {
            mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, nonce_counter, stream_block );

            for( i = 16; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        c = *input++;
        *output++ = (unsigned char)( c ^ stream_block[n] );

        n = ( n + 1 ) & 0x0F;
    }

    *nc_off = n;

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#endif /* !MBEDTLS_AES_ALT */

#if defined(MBEDTLS_SELF_TEST)
/*
 * AES test vectors from:
 *
 * http://csrc.nist.gov/archive/aes/rijndael/rijndael-vals.zip
 */
static const unsigned char aes_test_ecb_dec[3][16] =
{
    { 0x44, 0x41, 0x6A, 0xC2, 0xD1, 0xF5, 0x3C, 0x58,
      0x33, 0x03, 0x91, 0x7E, 0x6B, 0xE9, 0xEB, 0xE0 },
    { 0x48, 0xE3, 0x1E, 0x9E, 0x25, 0x67, 0x18, 0xF2,
      0x92, 0x29, 0x31, 0x9C, 0x19, 0xF1, 0x5B, 0xA4 },
    { 0x05, 0x8C, 0xCF, 0xFD, 0xBB, 0xCB, 0x38, 0x2D,
      0x1F, 0x6F, 0x56, 0x58, 0x5D, 0x8A, 0x4A, 0xDE }
};

static const unsigned char aes_test_ecb_enc[3][16] =
{
    { 0xC3, 0x4C, 0x05, 0x2C, 0xC0, 0xDA, 0x8D, 0x73,
      0x45, 0x1A, 0xFE, 0x5F, 0x03, 0xBE, 0x29, 0x7F },
    { 0xF3, 0xF6, 0x75, 0x2A, 0xE8, 0xD7, 0x83, 0x11,
      0x38, 0xF0, 0x41, 0x56, 0x06, 0x31, 0xB1, 0x14 },
    { 0x8B, 0x79, 0xEE, 0xCC, 0x93, 0xA0, 0xEE, 0x5D,
      0xFF, 0x30, 0xB4, 0xEA, 0x21, 0x63, 0x6D, 0xA4 }
};

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static const unsigned char aes_test_cbc_dec[3][16] =
{
    { 0xFA, 0xCA, 0x37, 0xE0, 0xB0, 0xC8, 0x53, 0x73,
      0xDF, 0x70, 0x6E, 0x73, 0xF7, 0xC9, 0xAF, 0x86 },
    { 0x5D, 0xF6, 0x78, 0xDD, 0x17, 0xBA, 0x4E, 0x75,
      0xB6, 0x17, 0x68, 0xC6, 0xAD, 0xEF, 0x7C, 0x7B },
    { 0x48, 0x04, 0xE1, 0x81, 0x8F, 0xE6, 0x29, 0x75,
      0x19, 0xA3, 0xE8, 0x8C, 0x57, 0x31, 0x04, 0x13 }
};

static const unsigned char aes_test_cbc_enc[3][16] =
{
    { 0x8A, 0x05, 0xFC, 0x5E, 0x09, 0x5A, 0xF4, 0x84,
      0x8A, 0x08, 0xD3, 0x28, 0xD3, 0x68, 0x8E, 0x3D },
    { 0x7B, 0xD9, 0x66, 0xD5, 0x3A, 0xD8, 0xC1, 0xBB,
      0x85, 0xD2, 0xAD, 0xFA, 0xE8, 0x7B, 0xB1, 0x04 },
    { 0xFE, 0x3C, 0x53, 0x65, 0x3E, 0x2F, 0x45, 0xB5,
      0x6F, 0xCD, 0x88, 0xB2, 0xCC, 0x89, 0x8F, 0xF0 }
};
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/*
 * AES-CFB128 test vectors from:
 *
 * http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
 */
static const unsigned char aes_test_cfb128_key[3][32] =
{
    { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
      0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C },
    { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
      0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
      0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B },
    { 0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
      0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
      0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
      0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4 }
};

static const unsigned char aes_test_cfb128_iv[16] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const unsigned char aes_test_cfb128_pt[64] =
{
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
    0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
    0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
    0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
    0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
    0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
    0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
};

static const unsigned char aes_test_cfb128_ct[3][64] =
{
    { 0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20,
      0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB, 0x4A,
      0xC8, 0xA6, 0x45, 0x37, 0xA0, 0xB3, 0xA9, 0x3F,
      0xCD, 0xE3, 0xCD, 0xAD, 0x9F, 0x1C, 0xE5, 0x8B,
      0x26, 0x75, 0x1F, 0x67, 0xA3, 0xCB, 0xB1, 0x40,
      0xB1, 0x80, 0x8C, 0xF1, 0x87, 0xA4, 0xF4, 0xDF,
      0xC0, 0x4B, 0x05, 0x35, 0x7C, 0x5D, 0x1C, 0x0E,
      0xEA, 0xC4, 0xC6, 0x6F, 0x9F, 0xF7, 0xF2, 0xE6 },
    { 0xCD, 0xC8, 0x0D, 0x6F, 0xDD, 0xF1, 0x8C, 0xAB,
      0x34, 0xC2, 0x59, 0x09, 0xC9, 0x9A, 0x41, 0x74,
      0x67, 0xCE, 0x7F, 0x7F, 0x81, 0x17, 0x36, 0x21,
      0x96, 0x1A, 0x2B, 0x70, 0x17, 0x1D, 0x3D, 0x7A,
      0x2E, 0x1E, 0x8A, 0x1D, 0xD5, 0x9B, 0x88, 0xB1,
      0xC8, 0xE6, 0x0F, 0xED, 0x1E, 0xFA, 0xC4, 0xC9,
      0xC0, 0x5F, 0x9F, 0x9C, 0xA9, 0x83, 0x4F, 0xA0,
      0x42, 0xAE, 0x8F, 0xBA, 0x58, 0x4B, 0x09, 0xFF },
    { 0xDC, 0x7E, 0x84, 0xBF, 0xDA, 0x79, 0x16, 0x4B,
      0x7E, 0xCD, 0x84, 0x86, 0x98, 0x5D, 0x38, 0x60,
      0x39, 0xFF, 0xED, 0x14, 0x3B, 0x28, 0xB1, 0xC8,
      0x32, 0x11, 0x3C, 0x63, 0x31, 0xE5, 0x40, 0x7B,
      0xDF, 0x10, 0x13, 0x24, 0x15, 0xE5, 0x4B, 0x92,
      0xA1, 0x3E, 0xD0, 0xA8, 0x26, 0x7A, 0xE2, 0xF9,
      0x75, 0xA3, 0x85, 0x74, 0x1A, 0xB9, 0xCE, 0xF8,
      0x20, 0x31, 0x62, 0x3D, 0x55, 0xB1, 0xE4, 0x71 }
};
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
/*
 * AES-OFB test vectors from:
 *
 * https://csrc.nist.gov/publications/detail/sp/800-38a/final
 */
static const unsigned char aes_test_ofb_key[3][32] =
{
    { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
      0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C },
    { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
      0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
      0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B },
    { 0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
      0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
      0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
      0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4 }
};

static const unsigned char aes_test_ofb_iv[16] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const unsigned char aes_test_ofb_pt[64] =
{
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
    0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
    0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
    0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
    0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
    0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
    0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
};

static const unsigned char aes_test_ofb_ct[3][64] =
{
    { 0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20,
      0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB, 0x4A,
      0x77, 0x89, 0x50, 0x8d, 0x16, 0x91, 0x8f, 0x03,
      0xf5, 0x3c, 0x52, 0xda, 0xc5, 0x4e, 0xd8, 0x25,
      0x97, 0x40, 0x05, 0x1e, 0x9c, 0x5f, 0xec, 0xf6,
      0x43, 0x44, 0xf7, 0xa8, 0x22, 0x60, 0xed, 0xcc,
      0x30, 0x4c, 0x65, 0x28, 0xf6, 0x59, 0xc7, 0x78,
      0x66, 0xa5, 0x10, 0xd9, 0xc1, 0xd6, 0xae, 0x5e },
    { 0xCD, 0xC8, 0x0D, 0x6F, 0xDD, 0xF1, 0x8C, 0xAB,
      0x34, 0xC2, 0x59, 0x09, 0xC9, 0x9A, 0x41, 0x74,
      0xfc, 0xc2, 0x8b, 0x8d, 0x4c, 0x63, 0x83, 0x7c,
      0x09, 0xe8, 0x17, 0x00, 0xc1, 0x10, 0x04, 0x01,
      0x8d, 0x9a, 0x9a, 0xea, 0xc0, 0xf6, 0x59, 0x6f,
      0x55, 0x9c, 0x6d, 0x4d, 0xaf, 0x59, 0xa5, 0xf2,
      0x6d, 0x9f, 0x20, 0x08, 0x57, 0xca, 0x6c, 0x3e,
      0x9c, 0xac, 0x52, 0x4b, 0xd9, 0xac, 0xc9, 0x2a },
    { 0xDC, 0x7E, 0x84, 0xBF, 0xDA, 0x79, 0x16, 0x4B,
      0x7E, 0xCD, 0x84, 0x86, 0x98, 0x5D, 0x38, 0x60,
      0x4f, 0xeb, 0xdc, 0x67, 0x40, 0xd2, 0x0b, 0x3a,
      0xc8, 0x8f, 0x6a, 0xd8, 0x2a, 0x4f, 0xb0, 0x8d,
      0x71, 0xab, 0x47, 0xa0, 0x86, 0xe8, 0x6e, 0xed,
      0xf3, 0x9d, 0x1c, 0x5b, 0xba, 0x97, 0xc4, 0x08,
      0x01, 0x26, 0x14, 0x1d, 0x67, 0xf3, 0x7b, 0xe8,
      0x53, 0x8f, 0x5a, 0x8b, 0xe7, 0x40, 0xe4, 0x84 }
};
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*
 * AES-CTR test vectors from:
 *
 * http://www.faqs.org/rfcs/rfc3686.html
 */

static const unsigned char aes_test_ctr_key[3][16] =
{
    { 0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC,
      0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E },
    { 0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7,
      0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63 },
    { 0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8,
      0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC }
};

static const unsigned char aes_test_ctr_nonce_counter[3][16] =
{
    { 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
    { 0x00, 0x6C, 0xB6, 0xDB, 0xC0, 0x54, 0x3B, 0x59,
      0xDA, 0x48, 0xD9, 0x0B, 0x00, 0x00, 0x00, 0x01 },
    { 0x00, 0xE0, 0x01, 0x7B, 0x27, 0x77, 0x7F, 0x3F,
      0x4A, 0x17, 0x86, 0xF0, 0x00, 0x00, 0x00, 0x01 }
};

static const unsigned char aes_test_ctr_pt[3][48] =
{
    { 0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
      0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67 },

    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F },

    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
      0x20, 0x21, 0x22, 0x23 }
};

static const unsigned char aes_test_ctr_ct[3][48] =
{
    { 0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79,
      0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8 },
    { 0x51, 0x04, 0xA1, 0x06, 0x16, 0x8A, 0x72, 0xD9,
      0x79, 0x0D, 0x41, 0xEE, 0x8E, 0xDA, 0xD3, 0x88,
      0xEB, 0x2E, 0x1E, 0xFC, 0x46, 0xDA, 0x57, 0xC8,
      0xFC, 0xE6, 0x30, 0xDF, 0x91, 0x41, 0xBE, 0x28 },
    { 0xC1, 0xCF, 0x48, 0xA8, 0x9F, 0x2F, 0xFD, 0xD9,
      0xCF, 0x46, 0x52, 0xE9, 0xEF, 0xDB, 0x72, 0xD7,
      0x45, 0x40, 0xA4, 0x2B, 0xDE, 0x6D, 0x78, 0x36,
      0xD5, 0x9A, 0x5C, 0xEA, 0xAE, 0xF3, 0x10, 0x53,
      0x25, 0xB2, 0x07, 0x2F }
};

static const int aes_test_ctr_len[3] =
    { 16, 32, 36 };
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_CIPHER_MODE_XTS)
/*
 * AES-XTS test vectors from:
 *
 * IEEE P1619/D16 Annex B
 * https://web.archive.org/web/20150629024421/http://grouper.ieee.org/groups/1619/email/pdf00086.pdf
 * (Archived from original at http://grouper.ieee.org/groups/1619/email/pdf00086.pdf)
 */
static const unsigned char aes_test_xts_key[][32] =
{
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 },
    { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
      0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 },
};

static const unsigned char aes_test_xts_pt32[][32] =
{
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
      0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
      0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
      0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 },
    { 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
      0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
      0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
      0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 },
};

static const unsigned char aes_test_xts_ct32[][32] =
{
    { 0x91, 0x7c, 0xf6, 0x9e, 0xbd, 0x68, 0xb2, 0xec,
      0x9b, 0x9f, 0xe9, 0xa3, 0xea, 0xdd, 0xa6, 0x92,
      0xcd, 0x43, 0xd2, 0xf5, 0x95, 0x98, 0xed, 0x85,
      0x8c, 0x02, 0xc2, 0x65, 0x2f, 0xbf, 0x92, 0x2e },
    { 0xc4, 0x54, 0x18, 0x5e, 0x6a, 0x16, 0x93, 0x6e,
      0x39, 0x33, 0x40, 0x38, 0xac, 0xef, 0x83, 0x8b,
      0xfb, 0x18, 0x6f, 0xff, 0x74, 0x80, 0xad, 0xc4,
      0x28, 0x93, 0x82, 0xec, 0xd6, 0xd3, 0x94, 0xf0 },
    { 0xaf, 0x85, 0x33, 0x6b, 0x59, 0x7a, 0xfc, 0x1a,
      0x90, 0x0b, 0x2e, 0xb2, 0x1e, 0xc9, 0x49, 0xd2,
      0x92, 0xdf, 0x4c, 0x04, 0x7e, 0x0b, 0x21, 0x53,
      0x21, 0x86, 0xa5, 0x97, 0x1a, 0x22, 0x7a, 0x89 },
};

static const unsigned char aes_test_xts_data_unit[][16] =
{
   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
   { 0x33, 0x33, 0x33, 0x33, 0x33, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
   { 0x33, 0x33, 0x33, 0x33, 0x33, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
};

#endif /* MBEDTLS_CIPHER_MODE_XTS */

/*
 * Checkup routine
 */
int mbedtls_aes_self_test( int verbose )
{
    int ret = 0, i, j, u, mode;
    unsigned int keybits;
    unsigned char key[32];
    unsigned char buf[64];
    const unsigned char *aes_tests;
#if defined(MBEDTLS_CIPHER_MODE_CBC) || defined(MBEDTLS_CIPHER_MODE_CFB)
    unsigned char iv[16];
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    unsigned char prv[16];
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR) || defined(MBEDTLS_CIPHER_MODE_CFB) || \
    defined(MBEDTLS_CIPHER_MODE_OFB)
    size_t offset;
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR) || defined(MBEDTLS_CIPHER_MODE_XTS)
    int len;
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    unsigned char nonce_counter[16];
    unsigned char stream_block[16];
#endif
    mbedtls_aes_context ctx;

    memset( key, 0, 32 );
    mbedtls_aes_init( &ctx );

    /*
     * ECB mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        keybits = 128 + u * 64;
        mode = i & 1;

        if( verbose != 0 )
            mbedtls_printf( "  AES-ECB-%3u (%s): ", keybits,
                            ( mode == MBEDTLS_AES_DECRYPT ) ? "dec" : "enc" );

        memset( buf, 0, 16 );

        if( mode == MBEDTLS_AES_DECRYPT )
        {
            ret = mbedtls_aes_setkey_dec( &ctx, key, keybits );
            aes_tests = aes_test_ecb_dec[u];
        }
        else
        {
            ret = mbedtls_aes_setkey_enc( &ctx, key, keybits );
            aes_tests = aes_test_ecb_enc[u];
        }

        /*
         * AES-192 is an optional feature that may be unavailable when
         * there is an alternative underlying implementation i.e. when
         * MBEDTLS_AES_ALT is defined.
         */
        if( ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED && keybits == 192 )
        {
            mbedtls_printf( "skipped\n" );
            continue;
        }
        else if( ret != 0 )
        {
            goto exit;
        }

        for( j = 0; j < 10000; j++ )
        {
            ret = mbedtls_aes_crypt_ecb( &ctx, mode, buf, buf );
            if( ret != 0 )
                goto exit;
        }

        if( memcmp( buf, aes_tests, 16 ) != 0 )
        {
            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    /*
     * CBC mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        keybits = 128 + u * 64;
        mode = i & 1;

        if( verbose != 0 )
            mbedtls_printf( "  AES-CBC-%3u (%s): ", keybits,
                            ( mode == MBEDTLS_AES_DECRYPT ) ? "dec" : "enc" );

        memset( iv , 0, 16 );
        memset( prv, 0, 16 );
        memset( buf, 0, 16 );

        if( mode == MBEDTLS_AES_DECRYPT )
        {
            ret = mbedtls_aes_setkey_dec( &ctx, key, keybits );
            aes_tests = aes_test_cbc_dec[u];
        }
        else
        {
            ret = mbedtls_aes_setkey_enc( &ctx, key, keybits );
            aes_tests = aes_test_cbc_enc[u];
        }

        /*
         * AES-192 is an optional feature that may be unavailable when
         * there is an alternative underlying implementation i.e. when
         * MBEDTLS_AES_ALT is defined.
         */
        if( ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED && keybits == 192 )
        {
            mbedtls_printf( "skipped\n" );
            continue;
        }
        else if( ret != 0 )
        {
            goto exit;
        }

        for( j = 0; j < 10000; j++ )
        {
            if( mode == MBEDTLS_AES_ENCRYPT )
            {
                unsigned char tmp[16];

                memcpy( tmp, prv, 16 );
                memcpy( prv, buf, 16 );
                memcpy( buf, tmp, 16 );
            }

            ret = mbedtls_aes_crypt_cbc( &ctx, mode, 16, iv, buf, buf );
            if( ret != 0 )
                goto exit;

        }

        if( memcmp( buf, aes_tests, 16 ) != 0 )
        {
            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
    /*
     * CFB128 mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        keybits = 128 + u * 64;
        mode = i & 1;

        if( verbose != 0 )
            mbedtls_printf( "  AES-CFB128-%3u (%s): ", keybits,
                            ( mode == MBEDTLS_AES_DECRYPT ) ? "dec" : "enc" );

        memcpy( iv,  aes_test_cfb128_iv, 16 );
        memcpy( key, aes_test_cfb128_key[u], keybits / 8 );

        offset = 0;
        ret = mbedtls_aes_setkey_enc( &ctx, key, keybits );
        /*
         * AES-192 is an optional feature that may be unavailable when
         * there is an alternative underlying implementation i.e. when
         * MBEDTLS_AES_ALT is defined.
         */
        if( ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED && keybits == 192 )
        {
            mbedtls_printf( "skipped\n" );
            continue;
        }
        else if( ret != 0 )
        {
            goto exit;
        }

        if( mode == MBEDTLS_AES_DECRYPT )
        {
            memcpy( buf, aes_test_cfb128_ct[u], 64 );
            aes_tests = aes_test_cfb128_pt;
        }
        else
        {
            memcpy( buf, aes_test_cfb128_pt, 64 );
            aes_tests = aes_test_cfb128_ct[u];
        }

        ret = mbedtls_aes_crypt_cfb128( &ctx, mode, 64, &offset, iv, buf, buf );
        if( ret != 0 )
            goto exit;

        if( memcmp( buf, aes_tests, 64 ) != 0 )
        {
            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
    /*
     * OFB mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        keybits = 128 + u * 64;
        mode = i & 1;

        if( verbose != 0 )
            mbedtls_printf( "  AES-OFB-%3u (%s): ", keybits,
                            ( mode == MBEDTLS_AES_DECRYPT ) ? "dec" : "enc" );

        memcpy( iv,  aes_test_ofb_iv, 16 );
        memcpy( key, aes_test_ofb_key[u], keybits / 8 );

        offset = 0;
        ret = mbedtls_aes_setkey_enc( &ctx, key, keybits );
        /*
         * AES-192 is an optional feature that may be unavailable when
         * there is an alternative underlying implementation i.e. when
         * MBEDTLS_AES_ALT is defined.
         */
        if( ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED && keybits == 192 )
        {
            mbedtls_printf( "skipped\n" );
            continue;
        }
        else if( ret != 0 )
        {
            goto exit;
        }

        if( mode == MBEDTLS_AES_DECRYPT )
        {
            memcpy( buf, aes_test_ofb_ct[u], 64 );
            aes_tests = aes_test_ofb_pt;
        }
        else
        {
            memcpy( buf, aes_test_ofb_pt, 64 );
            aes_tests = aes_test_ofb_ct[u];
        }

        ret = mbedtls_aes_crypt_ofb( &ctx, 64, &offset, iv, buf, buf );
        if( ret != 0 )
            goto exit;

        if( memcmp( buf, aes_tests, 64 ) != 0 )
        {
            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
    /*
     * CTR mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        mode = i & 1;

        if( verbose != 0 )
            mbedtls_printf( "  AES-CTR-128 (%s): ",
                            ( mode == MBEDTLS_AES_DECRYPT ) ? "dec" : "enc" );

        memcpy( nonce_counter, aes_test_ctr_nonce_counter[u], 16 );
        memcpy( key, aes_test_ctr_key[u], 16 );

        offset = 0;
        if( ( ret = mbedtls_aes_setkey_enc( &ctx, key, 128 ) ) != 0 )
            goto exit;

        len = aes_test_ctr_len[u];

        if( mode == MBEDTLS_AES_DECRYPT )
        {
            memcpy( buf, aes_test_ctr_ct[u], len );
            aes_tests = aes_test_ctr_pt[u];
        }
        else
        {
            memcpy( buf, aes_test_ctr_pt[u], len );
            aes_tests = aes_test_ctr_ct[u];
        }

        ret = mbedtls_aes_crypt_ctr( &ctx, len, &offset, nonce_counter,
                                     stream_block, buf, buf );
        if( ret != 0 )
            goto exit;

        if( memcmp( buf, aes_tests, len ) != 0 )
        {
            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_CIPHER_MODE_XTS)
    {
    static const int num_tests =
        sizeof(aes_test_xts_key) / sizeof(*aes_test_xts_key);
    mbedtls_aes_xts_context ctx_xts;

    /*
     * XTS mode
     */
    mbedtls_aes_xts_init( &ctx_xts );

    for( i = 0; i < num_tests << 1; i++ )
    {
        const unsigned char *data_unit;
        u = i >> 1;
        mode = i & 1;

        if( verbose != 0 )
            mbedtls_printf( "  AES-XTS-128 (%s): ",
                            ( mode == MBEDTLS_AES_DECRYPT ) ? "dec" : "enc" );

        memset( key, 0, sizeof( key ) );
        memcpy( key, aes_test_xts_key[u], 32 );
        data_unit = aes_test_xts_data_unit[u];

        len = sizeof( *aes_test_xts_ct32 );

        if( mode == MBEDTLS_AES_DECRYPT )
        {
            ret = mbedtls_aes_xts_setkey_dec( &ctx_xts, key, 256 );
            if( ret != 0)
                goto exit;
            memcpy( buf, aes_test_xts_ct32[u], len );
            aes_tests = aes_test_xts_pt32[u];
        }
        else
        {
            ret = mbedtls_aes_xts_setkey_enc( &ctx_xts, key, 256 );
            if( ret != 0)
                goto exit;
            memcpy( buf, aes_test_xts_pt32[u], len );
            aes_tests = aes_test_xts_ct32[u];
        }


        ret = mbedtls_aes_crypt_xts( &ctx_xts, mode, len, data_unit,
                                     buf, buf );
        if( ret != 0 )
            goto exit;

        if( memcmp( buf, aes_tests, len ) != 0 )
        {
            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    mbedtls_aes_xts_free( &ctx_xts );
    }
#endif /* MBEDTLS_CIPHER_MODE_XTS */

    ret = 0;

exit:
    if( ret != 0 && verbose != 0 )
        mbedtls_printf( "failed\n" );

    mbedtls_aes_free( &ctx );

    return( ret );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_AES_C */
