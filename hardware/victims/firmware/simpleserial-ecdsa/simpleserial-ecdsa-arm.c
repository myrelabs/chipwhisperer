//#include "hal.h"
#include "simpleserial.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(__arm__)

#include "mbedtls/config.h"
#include "mbedtls/ecdsa.h"
//#include "mbedtls/entropy.h"
//#include "mbedtls/ctr_drbg.h"


#define ECPARAMS   MBEDTLS_ECP_DP_BP256R1
#define FIELD_LEN  32
#define BASEPOINT_ORDER_LEN  FIELD_LEN


static int  key_is_empty;
mbedtls_ecdsa_context ctx;


void ecdsa_init(void)
{
    key_is_empty = 1;
    mbedtls_ecp_keypair_init( &ctx );  
}


/*
ToDo:
Replace NULL arguments of the mbedtls_ecp_mul call below with f_rng function: ctr_drbg
for entropy source - check  https://tls.mbed.org/kb/how-to/how_to_integrate_nv_seed
*/

//Xorshift RNGs
static uint32_t seed = 7;
static int myrand( void *rng_state, unsigned char *output, size_t len )
{
     size_t i;

     if( rng_state != NULL )
          rng_state  = NULL;

     for( i = 0; i < len; ++i ) {
        seed ^= (seed << 13);
        seed ^= (seed >> 17);
        seed ^= (seed << 5);         
        output[i] = seed & 0x000000FF;
     }     

     return( 0 );
}




uint8_t ecdsa_gen_key(uint8_t *pt)
{
    int      ret = 0;                     //longer type than the output type, but the simplesierial_get uses a sigle octet array in ack
    //const char *pers = "ecdsa";
    uint8_t  buf_for_compressed_point[1+FIELD_LEN];    
    size_t   compressed_point_length;
    //mbedtls_entropy_context entropy;
    //mbedtls_ctr_drbg_context ctr_drbg;

    //mbedtls_entropy_init( &entropy );        //!!!!!!!!!!! STM32F3 entropy mbedtls HowTo
    //mbedtls_ctr_drbg_init( &ctr_drbg );

    
    ((void) pt);

    if (key_is_empty) 
    {
        MBEDTLS_MPI_CHK( mbedtls_ecp_gen_key( ECPARAMS, &ctx, myrand, NULL ) );
        key_is_empty = 0;
    }    
    MBEDTLS_MPI_CHK( mbedtls_ecp_check_pub_priv( &ctx, &ctx) );

    memset(buf_for_compressed_point, 0, 1 + FIELD_LEN);
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_write_binary( &ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_COMPRESSED, &compressed_point_length, buf_for_compressed_point, 1 + FIELD_LEN ) );    
    simpleserial_put('r', compressed_point_length, buf_for_compressed_point);
   
cleanup:
    if (ret) simpleserial_put('r', sizeof(int), (uint8_t *)&ret);
    return( ret );
}




uint8_t ecdsa_set_key(uint8_t *pt)
{
    int      ret = 0;                     //longer type than the output type, but the simplesierial_get uses a sigle octet array in ack
    //const char *pers = "ecdsa";
    uint8_t  buf_for_compressed_point[1+FIELD_LEN];        
    size_t   compressed_point_length;
    //mbedtls_entropy_context entropy;
    //mbedtls_ctr_drbg_context ctr_drbg;
    
    //mbedtls_entropy_init( &entropy );        //!!!!!!!!!!! STM32F3 entropy mbedtls HowTo
    //mbedtls_ctr_drbg_init( &ctr_drbg );

    if (key_is_empty) 
    {
        MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &ctx.grp, ECPARAMS ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx.d, pt, FIELD_LEN ) );
        MBEDTLS_MPI_CHK( mbedtls_ecp_check_privkey( &ctx.grp, &ctx.d) );
        //MBEDTLS_MPI_CHK( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) );
        MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G, NULL, NULL ) );   //mbedtls_ctr_drbg_random, &ctr_drbg ) );

        key_is_empty = 0;
    }
    
    memset(buf_for_compressed_point, 0, 1 + FIELD_LEN);
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_write_binary( &ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_COMPRESSED, &compressed_point_length, buf_for_compressed_point, 1 + FIELD_LEN ) );
    simpleserial_put('r', compressed_point_length, buf_for_compressed_point);
   
cleanup:
    if (ret) simpleserial_put('r', sizeof(int), (uint8_t *)&ret);
    return( ret );
}




uint8_t ecdsa_gen_sig(uint8_t *pt)   //pt[0] contains the value of the length of the hash, the next pt[0] octets contains the hash value
{
    int      ret = 0;          //longer type than the output type, but the simplesierial_get uses a sigle octet array in ack
    
    uint8_t  buf_for_sig[2*(BASEPOINT_ORDER_LEN)]; 
    mbedtls_mpi r, s;

    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );
    MBEDTLS_MPI_CHK( mbedtls_ecdsa_sign( &ctx.grp, &r, &s, &ctx.d, pt+1, pt[0], myrand, NULL ) );
    //MBEDTLS_MPI_CHK( mbedtls_ecdsa_verify( &ctx.grp, pt+1, pt[0], &ctx.Q, &r, &s ) );

    memset(buf_for_sig, 0, 2*(BASEPOINT_ORDER_LEN));
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &r, buf_for_sig, BASEPOINT_ORDER_LEN ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &s, buf_for_sig + BASEPOINT_ORDER_LEN, BASEPOINT_ORDER_LEN ) );
    simpleserial_put('r', 2*(BASEPOINT_ORDER_LEN), buf_for_sig);

cleanup:
    if (ret) simpleserial_put('r', sizeof(int), (uint8_t *)&ret);

    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    return( ret );
}



#endif
