#include "fe25519.h"

void fe25519_invert(fe25519 *r, const fe25519 *x)
{
    fe25519 z2;
    fe25519 t0;
    fe25519 z9;
    fe25519 z11;
    int i;
    
    /* 2 */ fe25519_square(&z2,x);
    /* 4 */ fe25519_square(r,&z2);
    /* 8 */ fe25519_square(&t0,r);
    /* 9 */ fe25519_mul(&z9,&t0,x);
    /* 11 */ fe25519_mul(&z11,&z9,&z2);
    /* 22 */ fe25519_square(&t0,&z11);
    /* 2^5 - 2^0 = 31 */ fe25519_mul(&z2,&t0,&z9);

    /* 2^6 - 2^1 */ fe25519_square(&t0,&z2);
    /* 2^7 - 2^2 */ fe25519_square(r,&t0);
    /* 2^8 - 2^3 */ fe25519_square(&t0,r);
    /* 2^9 - 2^4 */ fe25519_square(r,&t0);
    /* 2^10 - 2^5 */ fe25519_square(&t0,r);
    /* 2^10 - 2^0 */ fe25519_mul(&z2,&t0,&z2);

    /* 2^11 - 2^1 */ fe25519_square(&t0,&z2);
    /* 2^12 - 2^2 */ fe25519_square(r,&t0);
    /* 2^20 - 2^10 */ for (i = 2;i < 10;i += 2) { fe25519_square(&t0,r); fe25519_square(r,&t0); }
    /* 2^20 - 2^0 */ fe25519_mul(&z9,r,&z2);

    /* 2^21 - 2^1 */ fe25519_square(&t0,&z9);
    /* 2^22 - 2^2 */ fe25519_square(r,&t0);
    /* 2^40 - 2^20 */ for (i = 2;i < 20;i += 2) { fe25519_square(&t0,r); fe25519_square(r,&t0); }
    /* 2^40 - 2^0 */ fe25519_mul(&t0,r,&z9);

    /* 2^41 - 2^1 */ fe25519_square(r,&t0);
    /* 2^42 - 2^2 */ fe25519_square(&t0,r);
    /* 2^50 - 2^10 */ for (i = 2;i < 10;i += 2) { fe25519_square(r,&t0); fe25519_square(&t0,r); }
    /* 2^50 - 2^0 */ fe25519_mul(&z2,&t0,&z2);

    /* 2^51 - 2^1 */ fe25519_square(&t0,&z2);
    /* 2^52 - 2^2 */ fe25519_square(r,&t0);
    /* 2^100 - 2^50 */ for (i = 2;i < 50;i += 2) { fe25519_square(&t0,r); fe25519_square(r,&t0); }
    /* 2^100 - 2^0 */ fe25519_mul(&z9,r,&z2);

    /* 2^101 - 2^1 */ fe25519_square(r,&z9);
    /* 2^102 - 2^2 */ fe25519_square(&t0,r);
    /* 2^200 - 2^100 */ for (i = 2;i < 100;i += 2) { fe25519_square(r,&t0); fe25519_square(&t0,r); }
    /* 2^200 - 2^0 */ fe25519_mul(r,&t0,&z9);

    /* 2^201 - 2^1 */ fe25519_square(&t0,r);
    /* 2^202 - 2^2 */ fe25519_square(r,&t0);
    /* 2^250 - 2^50 */ for (i = 2;i < 50;i += 2) { fe25519_square(&t0,r); fe25519_square(r,&t0); }
    /* 2^250 - 2^0 */ fe25519_mul(&t0,r,&z2);

    /* 2^251 - 2^1 */ fe25519_square(r,&t0);
    /* 2^252 - 2^2 */ fe25519_square(&t0,r);
    /* 2^253 - 2^3 */ fe25519_square(r,&t0);
    /* 2^254 - 2^4 */ fe25519_square(&t0,r);
    /* 2^255 - 2^5 */ fe25519_square(r,&t0);
    /* 2^255 - 21 */ fe25519_mul(r,r,&z11);
}
