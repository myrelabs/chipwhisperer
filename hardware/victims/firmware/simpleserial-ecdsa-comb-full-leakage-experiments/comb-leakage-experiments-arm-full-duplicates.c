#include <stdlib.h>
#include <string.h>
#include "hal.h"
#include "simpleserial.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"


#define ECPARAMS   MBEDTLS_ECP_DP_BP256R1
#define FIELD_LEN  32
#define COMB_MAX_D      ( MBEDTLS_ECP_MAX_BITS + 1 ) / 2



int ecp_precompute_comb( const mbedtls_ecp_group *grp,
                                mbedtls_ecp_point T[], const mbedtls_ecp_point *P,
                                unsigned char w, size_t d,
                                mbedtls_ecp_restart_ctx *rs_ctx );

int ecp_select_comb( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                            const mbedtls_ecp_point T[], unsigned char T_size,
                            unsigned char i );

void ecp_comb_recode_core( unsigned char x[], size_t d,
                                  unsigned char w, const mbedtls_mpi *m );


static mbedtls_ecp_group grp;

static unsigned char w;
static size_t d;

#define SIZE_OF_T 16
#define NR_OF_COPIES 4
static mbedtls_ecp_point TCopy[SIZE_OF_T*NR_OF_COPIES];
static mbedtls_ecp_point R;




void comb_init(void) 
{ 
    uint32_t i, j;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, ECPARAMS);
 
    w = 5; 
    d = ( grp.nbits + w - 1 ) / w;


    for( j = 0; j < NR_OF_COPIES; j++ )
	for( i = 0; i < SIZE_OF_T; i++ ) 
    	   mbedtls_ecp_point_init( TCopy + j*SIZE_OF_T + i ); 
       
       
    for( j = 0; j < NR_OF_COPIES; j++ )
    	ecp_precompute_comb(&grp, TCopy + j*SIZE_OF_T, &grp.G, w, d, NULL);
    
    mbedtls_ecp_point_init( &R );    
}



/*
pt[0] - index ind required to get TCopy[ind]
pt[1] - index of the TCopy array of precomputed points
function sends 64 bytes by simpleserial_put() - the point TCopy[ind]
*/
uint8_t select_comb(uint8_t *pt)
{
    int      ret = 0;
    uint8_t  buf_for_ec_point[2*(FIELD_LEN)]; 
    mbedtls_ecp_point* TSource;
 
    TSource = TCopy + pt[1]*SIZE_OF_T;
 
    trigger_high();
    MBEDTLS_MPI_CHK( ecp_select_comb( &grp, &R, TSource, SIZE_OF_T, *pt) );
    trigger_low();
    
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &R.X, buf_for_ec_point, FIELD_LEN ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &R.Y, buf_for_ec_point + FIELD_LEN, FIELD_LEN ) );
    simpleserial_put('r', 2*FIELD_LEN, buf_for_ec_point);

cleanup:
    if (ret) simpleserial_put('r', sizeof(int), (uint8_t *)&ret);

    return ret; 
}



uint8_t select_comb_no_output(uint8_t *pt)
{
    int      ret = 0;
    mbedtls_ecp_point* TSource;
 
    TSource = TCopy + pt[1]*SIZE_OF_T;
 
    trigger_high();
    MBEDTLS_MPI_CHK( ecp_select_comb( &grp, &R, TSource, SIZE_OF_T, *pt) );
    trigger_low();
    
cleanup:

    return ret; 
}




uint8_t call_recode(uint8_t *pt)
{
    int      ret = 0;
    unsigned char k[COMB_MAX_D + 1];
    mbedtls_mpi m; 
 
    mbedtls_mpi_init(&m);
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary(&m, pt+1 , pt[0]) );
    
    trigger_high();
    ecp_comb_recode_core( k, d, w, &m );
    trigger_low();
    simpleserial_put('r', d+1, k);

cleanup:
    if (ret) simpleserial_put('r', sizeof(int), (uint8_t *)&ret);
    
    mbedtls_mpi_free(&m);
    return ret;
}

