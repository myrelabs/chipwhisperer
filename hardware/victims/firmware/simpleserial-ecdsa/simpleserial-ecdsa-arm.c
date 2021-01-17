#include "hal.h"
#include "simpleserial.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(__arm__)

#include "mbedtls/ecdsa.h"


//#define mbedtls_calloc calloc
//#define mbedtls_free free

#define ECPARAMS   MBEDTLS_ECP_DP_BP256R1
#define FIELD_LEN  32

uint8_t buf[1+FIELD_LEN];

/*
ToDo:

1. Replace NULL arguments of the mbedtls_ecp_mul call below with f_rng function
2. Decomposite the function below into  ecdsa_init, ecdsa_set_key and add additional functions, 
       like e.g. ecdsa_sign,  and   int(*f_rng)(void *, unsigned char *, size_t) used by e.g., mbedtls_ecp_gen_key
3. Add return code (int) to the argument of simpleserial_put(): buf shall be concatenation of the compressed point and the ret value;
   then the value directly returned by e.g. ecdsa_set_key indicates whether  ret != 0
*/

uint8_t ecdsa_set_key(uint8_t *pt)
{
    int      ret = 0;                     //longer type than the output type, but the simplesierial_get uses a sigle octet array in ack
    size_t   compressed_point_length;
    mbedtls_ecdsa_context ctx;

    memset(buf, 0, 1 + FIELD_LEN);
    mbedtls_ecp_keypair_init( &ctx );        
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &ctx.grp, ECPARAMS ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx.d, pt, FIELD_LEN ) );
    //trigger_high();
    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G, NULL, NULL ) );
    //trigger_low();
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_write_binary( &ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_COMPRESSED, &compressed_point_length, buf, 1 + FIELD_LEN ) );

    //send back the compressed point
    simpleserial_put('r', compressed_point_length, buf);
    
cleanup:
    mbedtls_ecdsa_free( &ctx );
    return( ret );
}


#endif
