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



void ecp_comb_recode_core( unsigned char x[], size_t d,
                                  unsigned char w, const mbedtls_mpi *m );



#define NR_OF_COPIES 16


static unsigned char w;
static size_t d;
static mbedtls_mpi m[NR_OF_COPIES]; 
static unsigned char k[(COMB_MAX_D + 1)*NR_OF_COPIES];





void comb_recode_init(void) 
{
    uint8_t i; 
    
    w = 5; 
    d = 52;

    for (i=0 ; i < NR_OF_COPIES ; i++)
 	mbedtls_mpi_init(m+i);
}


//pt[0] indicates the index of memory region (copy), pt[1] is the length of the scalar, pt+2 points to the scalar itself

uint8_t call_recode(uint8_t *pt)
{
    int      ret = 0;
    uint8_t  index_of_memory_region;
    unsigned char* kk;
    
    index_of_memory_region = pt[0] % NR_OF_COPIES;
    kk = k + (COMB_MAX_D + 1)*index_of_memory_region;
 
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary(m + index_of_memory_region, pt+2 , pt[1]) );
    
    ecp_comb_recode_core( kk, d, w, m + index_of_memory_region );
    simpleserial_put('r', d+1, kk);

cleanup:
    if (ret) simpleserial_put('r', sizeof(int), (uint8_t *)&ret);
    
    return ret;
}




