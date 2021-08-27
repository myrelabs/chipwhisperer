#include <stdlib.h>
#include <string.h>
#include "hal.h"
#include "simpleserial.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"




#define ECPARAMS   MBEDTLS_ECP_DP_BP256R1
#define FIELD_LEN  32
#define COMB_MAX_D      ( MBEDTLS_ECP_MAX_BITS + 1 ) / 2
#define ALIGNED_DATA_SLOT  ( ( ( COMB_MAX_D >> 5 ) + 1 ) << 5 )



int ecp_comb_recode_scalar( const mbedtls_ecp_group *grp,
                                   const mbedtls_mpi *m,
                                   unsigned char k[COMB_MAX_D + 1],
                                   size_t d,
                                   unsigned char w,
                                   unsigned char *parity_trick );



#define NR_OF_COPIES 16

static mbedtls_ecp_group grp;
static unsigned char w;
static size_t d;
static mbedtls_mpi m[NR_OF_COPIES]; 
static unsigned char k[ALIGNED_DATA_SLOT*NR_OF_COPIES];





void comb_recode_init(void) 
{
    uint8_t i; 
    
    w = 5; 
    d = 52;

    for (i=0 ; i < NR_OF_COPIES ; i++)
 	mbedtls_mpi_init(m+i);
 	
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, ECPARAMS); 	
}


//pt[0] indicates the index of memory region (copy), pt[1] is the length of the scalar, pt+2 points to the scalar itself


uint8_t call_recode(uint8_t *pt)
{
    int      ret = 0;
    uint8_t  index_of_memory_region;
    unsigned char* kk;
    unsigned char parity_trick;
    
    index_of_memory_region = pt[0] % NR_OF_COPIES;
    kk = k + ALIGNED_DATA_SLOT*index_of_memory_region;
 
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary(m + index_of_memory_region, pt+2 , pt[1]) );
    MBEDTLS_MPI_CHK( ecp_comb_recode_scalar( &grp, m + index_of_memory_region, kk, d, w, &parity_trick ) );

    simpleserial_put('r', d+1, kk);

cleanup:
    if (ret) simpleserial_put('r', sizeof(int), (uint8_t *)&ret);
    
    return ret;
}




