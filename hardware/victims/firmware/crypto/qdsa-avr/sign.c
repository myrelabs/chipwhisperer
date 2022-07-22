#include "sign.h"
#include "hal.h"


int keypair(
        unsigned char *pk, 
        unsigned char *sk
        )
{
    /*
     * Generate a 64-byte pseudo-random string and a public
     * key x-coordinate on the Montgomery curve.
     * The secret key is clamped before usage.
     *
     * Input: 
     *      sk (64 bytes): 32 bytes of randomness (in lower bytes)
     *
     * Output: 
     *      pk (32 bytes): Public key, x-coordinate (no sign bit)
     *      sk (64 bytes): Pseudo-random secret
     */

    ecp R;
    fe25519 rx;

    hash(sk, sk, 32);
    sk[32] &= 248;
    sk[63] &= 127;
    sk[63] |= 64;

    group_scalar_get32(&rx, sk+32);
    ladder_base(&R, &rx);

    compress(&rx, &R);
    fe25519_pack(pk, &rx);

    return 0;
}

int sign(
        unsigned char *sm, unsigned long long *smlen,
        const unsigned char *m, unsigned long long mlen,
        const unsigned char *pk, const unsigned char *sk
        )
{
    /*
     * Generate a signature consisting of a 32-byte 
     * x-coordinate on the Montgomery curve and an 
     * integer modulo the curve order.
     * Append the message to the signature.
     *
     * Input: 
     *      m: Message
     *      mlen: Message length in bytes
     *      pk (32 bytes): Public key, x-coordinate (no sign bit)
     *      sk (64 bytes): Pseudo-random secret
     *
     * Output: 
     *      sm (64+mlen bytes): Signature + Message
     *      smlen: 64+mlen
     */

    unsigned long long i;
    ecp R;
    fe25519 rx;
    group_scalar r;

    *smlen = mlen+64;
    for(i=0;i<mlen;i++) { sm[64+i] = m[i]; }
    for(i=0;i<32;i++) { sm[32+i] = sk[i]; }
    hash(sm, sm+32, mlen+32);
    group_scalar_get64(&r, sm);
    
    //set 0 to lsb of the scalar:
    r.v[0] &= 0xFE;        //ToDo: to remove

    trigger_high();
    ladder_base_modified(&R, &r);   //ToDo: to remove _modified
    trigger_low();
    compress(&rx, &R);

    for(i=0;i<32;i++) { sm[32+i] = pk[i]; }
    for(i=0;i<32;i++) { sm[i] = rx.v[i]; }
    hash(sm, sm, mlen+64);
    group_scalar_get64(&R.X, sm);
    group_scalar_get32(&R.Z, sk+32);

    group_scalar_set_pos(&R.X);
    group_scalar_mul(&R.Z, &R.X, &R.Z);
    group_scalar_sub(&R.Z, &r, &R.Z);

    fe25519_pack(sm, &rx);
    group_scalar_pack(sm+32, &R.Z);

    return 0;
}

int verify(
        unsigned char *m, long long mlen,
        unsigned char *sm, unsigned long long smlen,
        const unsigned char *pk
        )
{
    /*
     * Verify correctness of a signature with respect
     * to a public key. Return 1 if correct, 0 if
     * incorrect, and return the message.
     *
     * Input: 
     *      sm (64+mlen bytes): Signature + Message
     *      smlen: 64+mlen
     *      pk (32 bytes): Public key, x-coordinate (no sign bit)
     *
     * Output: 
     *      0 if correct, 1 if incorrect
     *      m: Message
     *      mlen: Message length (bytes)
     */

    unsigned long long i;
    ecp sP, hQ;
    fe25519 rx, bZZ, bXZ, bXX;

    fe25519_unpack(&rx, sm);
    group_scalar_get32(&bZZ, sm+32);
    for(i=0;i<smlen-64;i++) { m[i] = sm[64+i]; }
    mlen = smlen-64;

    for(i=0;i<32;i++) { sm[32+i] = pk[i]; }
    hash(sm, sm, mlen+64);
    group_scalar_get64(&bXZ, sm);

    fe25519_unpack(&bXX, pk);
    decompress(&sP, &bXX);
    ladder(&hQ, &sP, &bXX, &bXZ);
    ladder_base(&sP, &bZZ);

    bValues(&bZZ, &bXZ, &bXX, &sP, &hQ);
    return check(&bZZ, &bXZ, &bXX, &rx);
}
