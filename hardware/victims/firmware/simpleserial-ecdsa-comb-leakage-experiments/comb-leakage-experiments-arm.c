#include "hal.h"
#include "simpleserial.h"




typedef struct
{
    int s;             
    uint32_t v;
} 
my_mpi;



typedef struct
{
    my_mpi X;          /*!<  the point's X coordinate  */
    my_mpi Y;          /*!<  the point's Y coordinate  */
}
my_ecp_point;



void my_mpi_safe_cond_assign( my_mpi *X, const my_mpi *Y, unsigned char assign )
{
    /* make sure assign is 0 or 1 in a time-constant manner */
    assign = (assign | (unsigned char)-assign) >> 7;

    X->s = X->s * ( 1 - assign ) + Y->s * assign;
    X->v = X->v * ( 1 - assign ) + Y->v * assign;
}


/*
 * Conditional point inversion: Q -> -Q = (Q.X, -Q.Y, Q.Z) without leak.
 * "inv" must be 0 (don't invert) or 1 (invert) or the result will be invalid
 */
static void my_ecp_safe_invert_jac( uint32_t p,
                            my_ecp_point *Q,
                            unsigned char inv )
{
    unsigned char nonzero;
    my_mpi mQY;
    
    mQY.s = 1;
    mQY.v = 0;

    /* Use the fact that -Q.Y mod P = P - Q.Y unless Q.Y == 0 */
    mQY.v = p - Q->Y.v;
    nonzero = Q->Y.v != 0;
    my_mpi_safe_cond_assign( &Q->Y, &mQY, inv & nonzero );
}
/*
 * Compute the representation of m that will be used with our comb method.
 *
 * The basic comb method is described in GECC 3.44 for example. We use a
 * modified version that provides resistance to SPA by avoiding zero
 * digits in the representation as in [3]. We modify the method further by
 * requiring that all K_i be odd, which has the small cost that our
 * representation uses one more K_i, due to carries.
 *
 * Also, for the sake of compactness, only the seven low-order bits of x[i]
 * are used to represent K_i, and the msb of x[i] encodes the the sign (s_i in
 * the paper): it is set if and only if if s_i == -1;
 *
 * Calling conventions:
 * - x is an array of size d + 1
 * - w is the size, ie number of teeth, of the comb, and must be between
 *   2 and 7 (in practice, between 2 and MBEDTLS_ECP_WINDOW_SIZE)
 * - m is the MPI, expected to be odd and such that bitlength(m) <= w * d
 *   (the result will be incorrect if these assumptions are not satisfied)
 */
 

/* 
static void ecp_comb_fixed( unsigned char x[], size_t d,
                            unsigned char w, const mbedtls_mpi *m )
{
    size_t i, j;
    unsigned char c, cc, adjust;

    memset( x, 0, d+1 );

    for( i = 0; i < d; i++ )
        for( j = 0; j < w; j++ )
            x[i] |= mbedtls_mpi_get_bit( m, i + d * j ) << j;

    c = 0;
    for( i = 1; i <= d; i++ )
    {
        cc   = x[i] & c;
        x[i] = x[i] ^ c;
        c = cc;

        adjust = 1 - ( x[i] & 0x01 );
        c   |= x[i] & ( x[i-1] * adjust );
        x[i] = x[i] ^ ( x[i-1] * adjust );
        x[i-1] |= adjust << 7;
    }
}
*/


/*
 * Select precomputed point: R = sign(i) * T[ abs(i) / 2 ]
 */
static void my_ecp_select_comb( uint32_t p, my_ecp_point *R,
                            const my_ecp_point T[], unsigned char t_len,
                            unsigned char i )
{
    unsigned char ii, j;

    /* Ignore the "sign" bit and scale down */
    ii =  ( i & 0x7Fu ) >> 1;

    /* Read the whole table to thwart cache-based timing attacks */
    for( j = 0; j < t_len; j++ )
    {
        my_mpi_safe_cond_assign( &R->X, &T[j].X, j == ii );
        my_mpi_safe_cond_assign( &R->Y, &T[j].Y, j == ii );
    }

    /* Safely invert result if i is "negative" */
    my_ecp_safe_invert_jac( p, R, i >> 7 );
}


#define SIZE_OF_T 16
static my_ecp_point TSource[SIZE_OF_T];

static uint32_t seed = 0;
static uint32_t modulus = 0;

static my_ecp_point TBuffer[511+SIZE_OF_T];




static void set_seed(uint32_t new_seed)
{
    if (new_seed != 0)
        seed = new_seed;
}



//Xorshift RNGs
static uint32_t myrand(void)
{
     seed ^= (seed << 13);
     seed ^= (seed >> 17);
     seed ^= (seed << 5);         
     return seed;
}



void comb_init(void) 
{
    int i;
    
    set_seed(0x29D14CA8);   //carefully chosen, trully random seed ;)
    modulus = myrand();

    for (i=0 ; i < SIZE_OF_T ; i++)
    {
        TSource[i].X.s = 1;
        TSource[i].X.v = myrand();
        TSource[i].Y.s = 1;
        TSource[i].Y.v = myrand();
    }
}


static uint32_t copyTSource(void)
{
    int           i;
    uint32_t      startIndex;
    my_ecp_point* TCopy;
       
    startIndex = myrand() % 512;
    TCopy = TBuffer + startIndex;
    
    for (i=0 ; i < SIZE_OF_T ; i++)
    {
        TCopy[i].X.s = TSource[i].X.s;
        TCopy[i].X.v = TSource[i].X.v;
        TCopy[i].Y.s = TSource[i].Y.s;
        TCopy[i].Y.v = TSource[i].Y.v;
    }
    
    return startIndex;
}


//reseed is needed after restart, to avoid using the old path after the init() function
uint8_t reseed(uint8_t *pt)
{
    set_seed(*((uint32_t*)pt));
    
    return 0;
}


uint8_t select_comb_from_TCopy(uint8_t *pt)
{
    uint32_t     startIndex;
//  uint32_t     output[2];
    my_ecp_point *TCopy;
    my_ecp_point R;
    
    startIndex = copyTSource();  //the array is copied to not include dependencies from the addresses of elements of T in the template
    TCopy = TBuffer + startIndex;
    trigger_high();
    my_ecp_select_comb( modulus, &R, TCopy, SIZE_OF_T, *pt);
    trigger_low();
    
//  output[0] = R.X.v;
//  output[1] = startIndex;   
    
//  simpleserial_put('r', 2*sizeof(uint32_t), (uint8_t*)output);
    
    return 0;
}



uint8_t select_comb_from_TSource(uint8_t *pt)
{
//  uint32_t     output[2];
    my_ecp_point R;
    
    trigger_high();
    my_ecp_select_comb( modulus, &R, TSource, SIZE_OF_T, *pt);
    trigger_low();
    
//  output[0] = R.X.v;
//  output[1] = startIndex;   
    
//  simpleserial_put('r', 2*sizeof(uint32_t), (uint8_t*)output);
    
    return 0;
}

