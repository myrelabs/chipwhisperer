#include <stdlib.h>
#include <string.h>
#include "hal.h"
#include "simpleserial.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"



#define ECPARAMS   MBEDTLS_ECP_DP_BP256R1
#define FIELD_LEN  32



int ecp_precompute_comb_copy( const mbedtls_ecp_group *grp,
                         mbedtls_ecp_point T[], const mbedtls_ecp_point *P,
                         unsigned char w, size_t d );


int ecp_select_comb_copy( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                     const mbedtls_ecp_point T[], unsigned char T_size,
                     unsigned char i );


static mbedtls_ecp_group grp;
static unsigned char w;
static size_t d;


#define SIZE_OF_T 16
#define ADDITIONAL_SIZE 33
static mbedtls_ecp_point TSource[SIZE_OF_T];
static mbedtls_ecp_point TBuffer[ADDITIONAL_SIZE+SIZE_OF_T];
static mbedtls_ecp_point R;


static uint32_t seed = 0;

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
    uint8_t i;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, ECPARAMS);
 
    w = 5; 
    d = ( grp.nbits + w - 1 ) / w;

    for( i = 0; i < SIZE_OF_T; i++ )
       mbedtls_ecp_point_init( &TSource[i] ); 
    ecp_precompute_comb_copy(&grp, TSource, &grp.G, w, d);

    mbedtls_ecp_point_init( &R );    

    set_seed(0x29D14CA8);   //carefully chosen, trully random seed ;)
}



static int copyTSource(mbedtls_ecp_point** PtrToTCopy, const uint8_t* permutationForCalloc)
{
    int      ret = 0;
    uint8_t  i,j;
    uint32_t startIndex;
    mbedtls_ecp_point* TCopy;
       
    startIndex = myrand() % (ADDITIONAL_SIZE + 1);
    TCopy = TBuffer + startIndex;
    
    for( i = 0; i < SIZE_OF_T; i++ )
       mbedtls_ecp_point_init( &TCopy[i] ); 
    
    for( i = 0; i < SIZE_OF_T; i++ ) {
    	j = permutationForCalloc[i];
       MBEDTLS_MPI_CHK( mbedtls_ecp_copy(&TCopy[j], &TSource[j]) );
    }   

cleanup:    
    *PtrToTCopy = TCopy;
    
    return ret;
}



static void freePointsOfTCopy(mbedtls_ecp_point* TCopy)
{
    uint8_t i;
    for( i = 0; i < SIZE_OF_T; i++ )
       mbedtls_ecp_point_free( &TCopy[i] ); 
}



//reseed is needed after restart, to avoid using the old path after the init() function
uint8_t reseed(uint8_t *pt)
{
    set_seed(*((uint32_t*)pt));
    
    return 0;
}



/*
pt[0] - index ind required to get TCopy[ind]
pt[1..16] - permutation used by copyTSource()
function sends 64 bytes by simpleserial_put() - the point TCopy[ind]
*/
uint8_t select_comb_from_TCopy(uint8_t *pt)
{
    int      ret = 0;
    uint8_t  buf_for_ec_point[2*(FIELD_LEN)]; 
    mbedtls_ecp_point* TCopy;
 
    MBEDTLS_MPI_CHK( copyTSource(&TCopy, pt+1) );  //the array is copied to not include dependencies from the addresses of elements of T in the template

    trigger_high();
    MBEDTLS_MPI_CHK( ecp_select_comb_copy( &grp, &R, TCopy, SIZE_OF_T, *pt) );
    trigger_low();
    
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &R.X, buf_for_ec_point, FIELD_LEN ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &R.Y, buf_for_ec_point + FIELD_LEN, FIELD_LEN ) );
    simpleserial_put('r', 2*FIELD_LEN, buf_for_ec_point);

cleanup:
    freePointsOfTCopy(TCopy);
    if (ret) simpleserial_put('r', sizeof(int), (uint8_t *)&ret);

    return ret; 
}



/*
*pt - index ind required to get TSource[ind]
function sends 64 bytes by simpleserial_put() - the point TSource[ind]
*/
uint8_t select_comb_from_TSource(uint8_t *pt)
{
    int      ret = 0;
    uint8_t  buf_for_ec_point[2*(FIELD_LEN)]; 
 
    trigger_high();
    MBEDTLS_MPI_CHK( ecp_select_comb_copy( &grp, &R, TSource, SIZE_OF_T, *pt) );
    trigger_low();
    
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &R.X, buf_for_ec_point, FIELD_LEN ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &R.Y, buf_for_ec_point + FIELD_LEN, FIELD_LEN ) );
    simpleserial_put('r', 2*FIELD_LEN, buf_for_ec_point);

cleanup:
    if (ret) simpleserial_put('r', sizeof(int), (uint8_t *)&ret);
    
    return ret;
}

