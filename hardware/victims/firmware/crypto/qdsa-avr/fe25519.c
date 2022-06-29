#include "fe25519.h"

/* reduction modulo 2^255-19 */
void fe25519_freeze(fe25519 *r)
{
  unsigned char c;
  fe25519 rt;
  c = bigint_subp(rt.v, r->v);
  fe25519_cmov(r,&rt,1-c);
  c = bigint_subp(rt.v, r->v);
  fe25519_cmov(r,&rt,1-c);
}

void fe25519_setzero(fe25519 *r)
{
  unsigned char i;
  for(i=0;i<32;i++)
    r->v[i]=0;
}

void fe25519_setone(fe25519 *r) 
{
  unsigned char i;
  r->v[0] = 1;
  for(i=1;i<32;i++) 
    r->v[i]=0;
}

void fe25519_cmov(fe25519 *r, const fe25519 *x, unsigned char b)
{
  unsigned char i;
  unsigned long mask = b;
  mask = -mask;
  for(i=0;i<32;i++) 
    r->v[i] ^= mask & (x->v[i] ^ r->v[i]);
}

void fe25519_unpack(fe25519 *r, const unsigned char x[32])
{
  unsigned char i;
  for(i=0;i<32;i++)
    r->v[i] = x[i];
  r->v[31] &= 127;
}

/* Assumes input x being reduced below 2^255 */
void fe25519_pack(unsigned char r[32], const fe25519 *x)
{
  unsigned char i;
  fe25519 y = *x;
  fe25519_freeze(&y);
  for(i=0;i<32;i++)
    r[i] = y.v[i];
}

void fe25519_copy(fe25519 *r, const fe25519 *x)
{
    unsigned char i;
    for(i=0;i<32;i++)
        r->v[i] = x->v[i];
}

static unsigned char equal(unsigned char a, unsigned char b)
{
    unsigned char x = a ^ b;
    return x == 0;
}

int fe25519_iszero(const fe25519 *x)
{
    unsigned char i;
    fe25519 t = *x;
    fe25519_freeze(&t);
    unsigned char r = equal(t.v[0],0);
    for(i=1;i<32;i++)
        r &= equal(t.v[i],0);
    return r;
}
    
void fe25519_mul(fe25519 *r, const fe25519 *x, const fe25519 *y)
{
  unsigned char t[64];
  bigint_mul256(t,x->v,y->v);
  fe25519_red(r,t);
} 

void fe25519_square(fe25519 *r, const fe25519 *x)
{
  unsigned char t[64];
  bigint_square256(t,x->v);
  fe25519_red(r,t);
}
