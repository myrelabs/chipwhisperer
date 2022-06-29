/*
 * File:    avrnacl_small/crypto_sign/sc25519.c
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Tue Aug 5 08:32:01 2014 +0200
 * Public Domain
 */

#include "fe25519.h"
#include "scalar.h"


/*Arithmetic modulo the group order m = 2^252 +  27742317777372353535851937790883648493 = 7237005577332262213973186563042994240857116359379907606001950938285454250989 */

static const unsigned char m[32] = {0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14, 
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};


static void bigint_cmov(unsigned char *r, const unsigned char *x, unsigned char b, unsigned char len)
{
  unsigned char i;
  unsigned char mask = b;
  mask = -mask;
  for(i=0;i<len;i++)
    r[i] ^= mask & (x[i] ^ r[i]);
}

/* Barrett reduction algorithm. Reduces an integer according to the modulus 2^252+.... See Hankerson et al. [p. 36] for more details. */
static void barrett_reduction(unsigned char* r, unsigned char* a) 
{
  unsigned char q1[66], q2[66], n1[33];
  unsigned char c;
  unsigned char q3[33] = {0x1B, 0x13, 0x2C, 0x0A, 0xA3, 0xE5, 0x9C, 0xED, 0xA7, 0x29, 0x63, 0x08, 0x5D, 0x21, 0x06, 0x21,
    0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F};
  unsigned char i;
  for (i=0; i<32; i++) n1[i] = m[i];
  n1[32] = 0;

  bigint_mul(q2, a+31, q3, 33);
  bigint_mul(q1, q2+33, n1, 33);

  /* m has only 253 bits, so q2 fits into 32 bytes */
  bigint_sub(r, a, q1, 32);
  c = bigint_sub(q2, r, m, 32);
  bigint_cmov(r, q2, 1-c, 32);
  c = bigint_sub(q2, r, m, 32);
  bigint_cmov(r, q2, 1-c, 32);
}


void group_scalar_get32(group_scalar *r, const unsigned char x[32])
{
    unsigned char i;
    for(i=0;i<32;i++) { r->v[i] = x[i]; }
}

// CAN JUST IMMEDIATELY REDUCE??
void group_scalar_get64(group_scalar *r, const unsigned char x[64])
{
    unsigned char i;
    unsigned char t[64];
    for(i=0;i<64;i++) { t[i] = x[i]; }
    barrett_reduction(r->v, t);
}

void group_scalar_pack(unsigned char r[32], const group_scalar *x)
{
    unsigned char i;
    for(i=0;i<32;i++)
    {
        r[i] = x->v[i];
    }
}

static void group_scalar_add(group_scalar *r, const group_scalar *x, const group_scalar *y)
{
  unsigned char c;
  unsigned char t[32];
  bigint_add(r->v,x->v,y->v,32);
  c = bigint_sub(t,r->v,m,32);
  bigint_cmov(r->v,t,1-c,32);
}


void group_scalar_sub(group_scalar *r, const group_scalar *x, const group_scalar *y)
{
    unsigned char b = 0;
    uint16_t t;
    unsigned char i;
    group_scalar d;

    for(i=0;i<32;i++)
    {
        t = m[i] - y->v[i] - b;
        d.v[i] = t & 255;
        b = (t >> 8) & 1;
    }
    group_scalar_add(r,x,&d);
}

void group_scalar_mul(group_scalar *r, const group_scalar *x, const group_scalar *y)
{
    unsigned char t[64];
    bigint_mul256(t, x->v, y->v);
    barrett_reduction(r->v, t);
}

static void group_scalar_setzero(group_scalar *r)
{
    unsigned char i;
    for(i=0;i<32;i++) { r->v[i] = 0; }
}

static void group_scalar_negate(group_scalar *r, const group_scalar *x)
{
    group_scalar t;
    group_scalar_setzero(&t);
    group_scalar_sub(r,&t,x);
}

void group_scalar_set_pos(group_scalar *r)
{
    if ( r->v[0] & 1 ) { group_scalar_negate(r, r); }
}
