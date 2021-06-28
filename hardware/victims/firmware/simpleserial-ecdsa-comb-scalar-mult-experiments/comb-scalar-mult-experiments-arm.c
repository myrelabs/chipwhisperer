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


int ecp_precompute_comb( const mbedtls_ecp_group *grp,
                                mbedtls_ecp_point T[], const mbedtls_ecp_point *P,
                                unsigned char w, size_t d,
                                mbedtls_ecp_restart_ctx *rs_ctx );

void ecp_comb_recode_core( unsigned char x[], size_t d,
                                  unsigned char w, const mbedtls_mpi *m );

void calculate_T_of_grp(mbedtls_ecp_group *grp, unsigned char w);



#define NR_OF_COPIES 3


static mbedtls_ecdsa_context ctx[NR_OF_COPIES];
static unsigned char w;
static size_t d;
static mbedtls_ecp_point R;

//static unsigned char memory_buf[8000];



static uint32_t seed = 7;


static void set_seed(uint32_t new_seed)
{
    if (new_seed != 0)
        seed = new_seed;
}


//Xorshift RNGs
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


//reseed is needed after restart, to avoid using the old path after the init() function
uint8_t reseed(uint8_t *pt)
{
    set_seed(*((uint32_t*)pt));
    
    return 0;
}




void comb_scalar_mult_init(void) 
{
    uint8_t i; 
    
    w = 5; 

    //mbedtls_memory_buffer_alloc_init( memory_buf, sizeof(memory_buf) );
    for (i=0 ; i < NR_OF_COPIES ; i++) {
        mbedtls_ecp_keypair_init( &ctx[i] );  
        mbedtls_ecp_group_load( &ctx[i].grp, ECPARAMS );
        calculate_T_of_grp(&ctx[i].grp, w);
    }

    d = ( ctx[0].grp.nbits + w - 1 ) / w;
    mbedtls_ecp_point_init( &R );    
    set_seed(0x29D14CA8);   //carefully chosen, trully random seed ;)
}


//pt[0] indicates the length of the scalar, pt+1 points to the scalar itself

uint8_t call_recode(uint8_t *pt)
{
    int      ret = 0;
    unsigned char k[COMB_MAX_D + 1];
    mbedtls_mpi m; 
 
    mbedtls_mpi_init(&m);
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary(&m, pt+1 , pt[0]) );
    
    ecp_comb_recode_core( k, d, w, &m );
    simpleserial_put('r', d+1, k);

cleanup:
    if (ret) simpleserial_put('r', sizeof(int), (uint8_t *)&ret);
    
    mbedtls_mpi_free(&m);
    return ret;
}


//pt[0] indicates the index of the context, pt+1 is the pointer to the scalar

uint8_t ecdsa_set_key(uint8_t *pt)
{
    uint8_t  i = pt[0] % NR_OF_COPIES;
    int      ret = 0;                     //longer type than the output type, but the simplesierial_get uses a sigle octet array in ack
    //const char *pers = "ecdsa";
    uint8_t  buf_for_compressed_point[1+FIELD_LEN];        
    size_t   compressed_point_length;
    //mbedtls_entropy_context entropy;
    //mbedtls_ctr_drbg_context ctr_drbg;
    
    //mbedtls_entropy_init( &entropy );        //!!!!!!!!!!! STM32F3 entropy mbedtls HowTo
    //mbedtls_ctr_drbg_init( &ctr_drbg );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx[i].d, pt+1, FIELD_LEN ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_check_privkey( &ctx[i].grp, &ctx[i].d) );
    //MBEDTLS_MPI_CHK( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mul( &ctx[i].grp, &ctx[i].Q, &ctx[i].d, &ctx[i].grp.G, myrand, NULL ) );   //mbedtls_ctr_drbg_random, &ctr_drbg ) );
    
    memset(buf_for_compressed_point, 0, 1 + FIELD_LEN);
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_write_binary( &ctx[i].grp, &ctx[i].Q, MBEDTLS_ECP_PF_COMPRESSED, &compressed_point_length, buf_for_compressed_point, 1 + FIELD_LEN ) );
    simpleserial_put('r', compressed_point_length, buf_for_compressed_point);
   
cleanup:
    if (ret) simpleserial_put('r', sizeof(int), (uint8_t *)&ret);
    return( ret );
}


