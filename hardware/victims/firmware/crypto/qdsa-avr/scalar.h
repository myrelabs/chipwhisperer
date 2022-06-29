#ifndef SC25519_H
#define SC25519_H

#include "fe25519.h"

typedef fe25519 group_scalar;

void group_scalar_get32(group_scalar *r, const unsigned char x[32]);
void group_scalar_get64(group_scalar *r, const unsigned char x[64]);
void group_scalar_pack(unsigned char r[32], const group_scalar *x);

void group_scalar_sub(group_scalar *r, const group_scalar *x, const group_scalar *y);
void group_scalar_mul(group_scalar *r, const group_scalar *x, const group_scalar *y);
void group_scalar_set_pos(group_scalar *r);

extern unsigned char bigint_mul(unsigned char *r, const unsigned char *x, const unsigned char *y, unsigned char);
extern unsigned char bigint_add(unsigned char *r, const unsigned char *x, const unsigned char *y, unsigned char);
extern unsigned char bigint_sub(unsigned char *r, const unsigned char *x, const unsigned char *y, unsigned char);

#endif
