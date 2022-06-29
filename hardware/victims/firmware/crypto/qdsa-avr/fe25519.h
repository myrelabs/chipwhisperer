#ifndef FE25519_H
#define FE25519_H

#define fe25519_add avrnacl_fe25519_add
#define fe25519_sub avrnacl_fe25519_sub
#define fe25519_red avrnacl_fe25519_red

#include <inttypes.h>

typedef uint32_t crypto_uint32;
typedef struct
{
  unsigned char v[32];
}
fe25519;

void fe25519_freeze(fe25519 *r);
void fe25519_unpack(fe25519 *r, const unsigned char x[32]);
void fe25519_pack(unsigned char r[32], const fe25519 *x);
void fe25519_copy(fe25519 *r, const fe25519 *x);

int fe25519_iszero(const fe25519 *x);
void fe25519_cmov(fe25519 *r, const fe25519 *x, unsigned char b);
void fe25519_setone(fe25519 *r);
void fe25519_setzero(fe25519 *r);

void fe25519_mul(fe25519 *r, const fe25519 *x, const fe25519 *y);
void fe25519_mul121666(fe25519 *r, const fe25519 *x);
void fe25519_square(fe25519 *r, const fe25519 *x);
void fe25519_invert(fe25519 *r, const fe25519 *x);

//Assembler Routines
extern void fe25519_add(fe25519 *r, const fe25519 *x, const fe25519 *y);
extern void fe25519_sub(fe25519 *r, const fe25519 *x, const fe25519 *y);
extern void fe25519_red(fe25519 *r, unsigned char *C);
extern char bigint_subp(unsigned char* r, const unsigned char* a);
extern char bigint_mul256(unsigned char* r, const unsigned char* a, const unsigned char* b);
extern char bigint_square256(unsigned char* r, const unsigned char* a);

#endif
