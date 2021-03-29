#include "mbedtls/ecp.h"
#include "mbedtls/threading.h"
//#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if !defined(MBEDTLS_ECP_ALT)


#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include "mbedtls/ecp_internal.h"


#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif



#define MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED -0x006E


/*
 * Wrapper around fast quasi-modp functions, with fall-back to mbedtls_mpi_mod_mpi.
 * See the documentation of struct mbedtls_ecp_group.
 *
 * This function is in the critial loop for mbedtls_ecp_mul, so pay attention to perf.
 */
static int ecp_modp( mbedtls_mpi *N, const mbedtls_ecp_group *grp )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( grp->modp == NULL )
        return( mbedtls_mpi_mod_mpi( N, N, &grp->P ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    if( ( N->s < 0 && mbedtls_mpi_cmp_int( N, 0 ) != 0 ) ||
        mbedtls_mpi_bitlen( N ) > 2 * grp->pbits )
    {
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    MBEDTLS_MPI_CHK( grp->modp( N ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    while( N->s < 0 && mbedtls_mpi_cmp_int( N, 0 ) != 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( N, N, &grp->P ) );

    while( mbedtls_mpi_cmp_mpi( N, &grp->P ) >= 0 )
        /* we known P, N and the result are positive */
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( N, N, &grp->P ) );

cleanup:
    return( ret );
}

/*
 * Fast mod-p functions expect their argument to be in the 0..p^2 range.
 *
 * In order to guarantee that, we need to ensure that operands of
 * mbedtls_mpi_mul_mpi are in the 0..p range. So, after each operation we will
 * bring the result back to this range.
 *
 * The following macros are shortcuts for doing that.
 */

/*
 * Reduce a mbedtls_mpi mod p in-place, general case, to use after mbedtls_mpi_mul_mpi
 */
#define MOD_MUL( N )                                                    \
    do                                                                  \
    {                                                                   \
        MBEDTLS_MPI_CHK( ecp_modp( &(N), grp ) );                       \
    } while( 0 )

static inline int mbedtls_mpi_mul_mod( const mbedtls_ecp_group *grp,
                                       mbedtls_mpi *X,
                                       const mbedtls_mpi *A,
                                       const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( X, A, B ) );
    MOD_MUL( *X );
cleanup:
    return( ret );
}

/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_sub_mpi
 * N->s < 0 is a very fast test, which fails only if N is 0
 */
#define MOD_SUB( N )                                                    \
    while( (N).s < 0 && mbedtls_mpi_cmp_int( &(N), 0 ) != 0 )           \
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &(N), &(N), &grp->P ) )

static inline int mbedtls_mpi_sub_mod( const mbedtls_ecp_group *grp,
                                       mbedtls_mpi *X,
                                       const mbedtls_mpi *A,
                                       const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( X, A, B ) );
    MOD_SUB( *X );
cleanup:
    return( ret );
}

/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_add_mpi and mbedtls_mpi_mul_int.
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */
#define MOD_ADD( N )                                                    \
    while( mbedtls_mpi_cmp_mpi( &(N), &grp->P ) >= 0 )                  \
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( &(N), &(N), &grp->P ) )

static inline int mbedtls_mpi_add_mod( const mbedtls_ecp_group *grp,
                                       mbedtls_mpi *X,
                                       const mbedtls_mpi *A,
                                       const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( X, A, B ) );
    MOD_ADD( *X );
cleanup:
    return( ret );
}

static inline int mbedtls_mpi_shift_l_mod( const mbedtls_ecp_group *grp,
                                           mbedtls_mpi *X,
                                           size_t count )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( X, count ) );
    MOD_ADD( *X );
cleanup:
    return( ret );
}

/*
 * For curves in short Weierstrass form, we do all the internal operations in
 * Jacobian coordinates.
 *
 * For multiplication, we'll use a comb method with coutermeasueres against
 * SPA, hence timing attacks.
 */

/*
 * Normalize jacobian coordinates so that Z == 0 || Z == 1  (GECC 3.2.1)
 * Cost: 1N := 1I + 3M + 1S
 */
static int ecp_normalize_jac( const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt )
{
    if( mbedtls_mpi_cmp_int( &pt->Z, 0 ) == 0 )
        return( 0 );

#if defined(MBEDTLS_ECP_NORMALIZE_JAC_ALT)
    if( mbedtls_internal_ecp_grp_capable( grp ) )
        return( mbedtls_internal_ecp_normalize_jac( grp, pt ) );
#endif /* MBEDTLS_ECP_NORMALIZE_JAC_ALT */

#if defined(MBEDTLS_ECP_NO_FALLBACK) && defined(MBEDTLS_ECP_NORMALIZE_JAC_ALT)
    return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi Zi, ZZi;
    mbedtls_mpi_init( &Zi ); mbedtls_mpi_init( &ZZi );

    /*
     * X = X / Z^2  mod p
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &Zi,      &pt->Z,     &grp->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &ZZi,     &Zi,        &Zi     ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &pt->X,   &pt->X,     &ZZi    ) );

    /*
     * Y = Y / Z^3  mod p
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &pt->Y,   &pt->Y,     &ZZi    ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &pt->Y,   &pt->Y,     &Zi     ) );

    /*
     * Z = 1
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &pt->Z, 1 ) );

cleanup:

    mbedtls_mpi_free( &Zi ); mbedtls_mpi_free( &ZZi );

    return( ret );
#endif /* !defined(MBEDTLS_ECP_NO_FALLBACK) || !defined(MBEDTLS_ECP_NORMALIZE_JAC_ALT) */
}

/*
 * Normalize jacobian coordinates of an array of (pointers to) points,
 * using Montgomery's trick to perform only one inversion mod P.
 * (See for example Cohen's "A Course in Computational Algebraic Number
 * Theory", Algorithm 10.3.4.)
 *
 * Warning: fails (returning an error) if one of the points is zero!
 * This should never happen, see choice of w in ecp_mul_comb().
 *
 * Cost: 1N(t) := 1I + (6t - 3)M + 1S
 */
static int ecp_normalize_jac_many( const mbedtls_ecp_group *grp,
                                   mbedtls_ecp_point *T[], size_t T_size )
{
    if( T_size < 2 )
        return( ecp_normalize_jac( grp, *T ) );

#if defined(MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT)
    if( mbedtls_internal_ecp_grp_capable( grp ) )
        return( mbedtls_internal_ecp_normalize_jac_many( grp, T, T_size ) );
#endif

#if defined(MBEDTLS_ECP_NO_FALLBACK) && defined(MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT)
    return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;
    mbedtls_mpi *c, u, Zi, ZZi;

    if( ( c = mbedtls_calloc( T_size, sizeof( mbedtls_mpi ) ) ) == NULL )
        return( MBEDTLS_ERR_ECP_ALLOC_FAILED );

    for( i = 0; i < T_size; i++ )
        mbedtls_mpi_init( &c[i] );

    mbedtls_mpi_init( &u ); mbedtls_mpi_init( &Zi ); mbedtls_mpi_init( &ZZi );

    /*
     * c[i] = Z_0 * ... * Z_i
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &c[0], &T[0]->Z ) );
    for( i = 1; i < T_size; i++ )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &c[i], &c[i-1], &T[i]->Z ) );
    }

    /*
     * u = 1 / (Z_0 * ... * Z_n) mod P
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &u, &c[T_size-1], &grp->P ) );

    for( i = T_size - 1; ; i-- )
    {
        /*
         * Zi = 1 / Z_i mod p
         * u = 1 / (Z_0 * ... * Z_i) mod P
         */
        if( i == 0 ) {
            MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &Zi, &u ) );
        }
        else
        {
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &Zi, &u, &c[i-1]  ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &u,  &u, &T[i]->Z ) );
        }

        /*
         * proceed as in normalize()
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &ZZi,     &Zi,      &Zi  ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T[i]->X, &T[i]->X, &ZZi ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T[i]->Y, &T[i]->Y, &ZZi ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T[i]->Y, &T[i]->Y, &Zi  ) );

        /*
         * Post-precessing: reclaim some memory by shrinking coordinates
         * - not storing Z (always 1)
         * - shrinking other coordinates, but still keeping the same number of
         *   limbs as P, as otherwise it will too likely be regrown too fast.
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( &T[i]->X, grp->P.n ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( &T[i]->Y, grp->P.n ) );
        mbedtls_mpi_free( &T[i]->Z );

        if( i == 0 )
            break;
    }

cleanup:

    mbedtls_mpi_free( &u ); mbedtls_mpi_free( &Zi ); mbedtls_mpi_free( &ZZi );
    for( i = 0; i < T_size; i++ )
        mbedtls_mpi_free( &c[i] );
    mbedtls_free( c );

    return( ret );
#endif /* !defined(MBEDTLS_ECP_NO_FALLBACK) || !defined(MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT) */
}

/*
 * Conditional point inversion: Q -> -Q = (Q.X, -Q.Y, Q.Z) without leak.
 * "inv" must be 0 (don't invert) or 1 (invert) or the result will be invalid
 */
static int ecp_safe_invert_jac( const mbedtls_ecp_group *grp,
                            mbedtls_ecp_point *Q,
                            unsigned char inv )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char nonzero;
    mbedtls_mpi mQY;

    mbedtls_mpi_init( &mQY );

    /* Use the fact that -Q.Y mod P = P - Q.Y unless Q.Y == 0 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &mQY, &grp->P, &Q->Y ) );
    nonzero = mbedtls_mpi_cmp_int( &Q->Y, 0 ) != 0;
    MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &Q->Y, &mQY, inv & nonzero ) );

cleanup:
    mbedtls_mpi_free( &mQY );

    return( ret );
}

/*
 * Point doubling R = 2 P, Jacobian coordinates
 *
 * Based on http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2 .
 *
 * We follow the variable naming fairly closely. The formula variations that trade a MUL for a SQR
 * (plus a few ADDs) aren't useful as our bignum implementation doesn't distinguish squaring.
 *
 * Standard optimizations are applied when curve parameter A is one of { 0, -3 }.
 *
 * Cost: 1D := 3M + 4S          (A ==  0)
 *             4M + 4S          (A == -3)
 *             3M + 6S + 1a     otherwise
 */
static int ecp_double_jac( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                           const mbedtls_ecp_point *P )
{
#if defined(MBEDTLS_ECP_DOUBLE_JAC_ALT)
    if( mbedtls_internal_ecp_grp_capable( grp ) )
        return( mbedtls_internal_ecp_double_jac( grp, R, P ) );
#endif /* MBEDTLS_ECP_DOUBLE_JAC_ALT */

#if defined(MBEDTLS_ECP_NO_FALLBACK) && defined(MBEDTLS_ECP_DOUBLE_JAC_ALT)
    return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi M, S, T, U;

    mbedtls_mpi_init( &M ); mbedtls_mpi_init( &S ); mbedtls_mpi_init( &T ); mbedtls_mpi_init( &U );

    /* Special case for A = -3 */
    if( grp->A.p == NULL )
    {
        /* M = 3(X + Z^2)(X - Z^2) */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &P->Z,  &P->Z   ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod( grp, &T,  &P->X,  &S      ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &U,  &P->X,  &S      ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &T,     &U      ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int( &M,  &S,     3       ) ); MOD_ADD( M );
    }
    else
    {
        /* M = 3.X^2 */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &P->X,  &P->X   ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int( &M,  &S,     3       ) ); MOD_ADD( M );

        /* Optimize away for "koblitz" curves with A = 0 */
        if( mbedtls_mpi_cmp_int( &grp->A, 0 ) != 0 )
        {
            /* M += A.Z^4 */
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &P->Z,  &P->Z   ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T,  &S,     &S      ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &T,     &grp->A ) );
            MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod( grp, &M,  &M,     &S      ) );
        }
    }

    /* S = 4.X.Y^2 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T,  &P->Y,  &P->Y   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l_mod( grp, &T,  1               ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &P->X,  &T      ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l_mod( grp, &S,  1               ) );

    /* U = 8.Y^4 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &U,  &T,     &T      ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l_mod( grp, &U,  1               ) );

    /* T = M^2 - 2.S */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T,  &M,     &M      ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &T,  &T,     &S      ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &T,  &T,     &S      ) );

    /* S = M(S - T) - U */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &S,  &S,     &T      ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &S,  &S,     &M      ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &S,  &S,     &U      ) );

    /* U = 2.Y.Z */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &U,  &P->Y,  &P->Z   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l_mod( grp, &U,  1               ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->X, &T ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->Y, &S ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->Z, &U ) );

cleanup:
    mbedtls_mpi_free( &M ); mbedtls_mpi_free( &S ); mbedtls_mpi_free( &T ); mbedtls_mpi_free( &U );

    return( ret );
#endif /* !defined(MBEDTLS_ECP_NO_FALLBACK) || !defined(MBEDTLS_ECP_DOUBLE_JAC_ALT) */
}

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 *
 * The coordinates of Q must be normalized (= affine),
 * but those of P don't need to. R is not normalized.
 *
 * Special cases: (1) P or Q is zero, (2) R is zero, (3) P == Q.
 * None of these cases can happen as intermediate step in ecp_mul_comb():
 * - at each step, P, Q and R are multiples of the base point, the factor
 *   being less than its order, so none of them is zero;
 * - Q is an odd multiple of the base point, P an even multiple,
 *   due to the choice of precomputed points in the modified comb method.
 * So branches for these cases do not leak secret information.
 *
 * We accept Q->Z being unset (saving memory in tables) as meaning 1.
 *
 * Cost: 1A := 8M + 3S
 */
static int ecp_add_mixed( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                          const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q )
{
#if defined(MBEDTLS_ECP_ADD_MIXED_ALT)
    if( mbedtls_internal_ecp_grp_capable( grp ) )
        return( mbedtls_internal_ecp_add_mixed( grp, R, P, Q ) );
#endif /* MBEDTLS_ECP_ADD_MIXED_ALT */

#if defined(MBEDTLS_ECP_NO_FALLBACK) && defined(MBEDTLS_ECP_ADD_MIXED_ALT)
    return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi T1, T2, T3, T4, X, Y, Z;

    /*
     * Trivial cases: P == 0 or Q == 0 (case 1)
     */
    if( mbedtls_mpi_cmp_int( &P->Z, 0 ) == 0 )
        return( mbedtls_ecp_copy( R, Q ) );

    if( Q->Z.p != NULL && mbedtls_mpi_cmp_int( &Q->Z, 0 ) == 0 )
        return( mbedtls_ecp_copy( R, P ) );

    /*
     * Make sure Q coordinates are normalized
     */
    if( Q->Z.p != NULL && mbedtls_mpi_cmp_int( &Q->Z, 1 ) != 0 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    mbedtls_mpi_init( &T1 ); mbedtls_mpi_init( &T2 ); mbedtls_mpi_init( &T3 ); mbedtls_mpi_init( &T4 );
    mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &Z );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T1,  &P->Z,  &P->Z ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T2,  &T1,    &P->Z ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T1,  &T1,    &Q->X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T2,  &T2,    &Q->Y ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &T1,  &T1,    &P->X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &T2,  &T2,    &P->Y ) );

    /* Special cases (2) and (3) */
    if( mbedtls_mpi_cmp_int( &T1, 0 ) == 0 )
    {
        if( mbedtls_mpi_cmp_int( &T2, 0 ) == 0 )
        {
            ret = ecp_double_jac( grp, R, P );
            goto cleanup;
        }
        else
        {
            ret = mbedtls_ecp_set_zero( R );
            goto cleanup;
        }
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &Z,   &P->Z,  &T1   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T3,  &T1,    &T1   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T4,  &T3,    &T1   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T3,  &T3,    &P->X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &T1, &T3 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l_mod( grp, &T1,  1     ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &X,   &T2,    &T2   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &X,   &X,     &T1   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &X,   &X,     &T4   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &T3,  &T3,    &X    ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T3,  &T3,    &T2   ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &T4,  &T4,    &P->Y ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &Y,   &T3,    &T4   ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->X, &X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->Y, &Y ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &R->Z, &Z ) );

cleanup:

    mbedtls_mpi_free( &T1 ); mbedtls_mpi_free( &T2 ); mbedtls_mpi_free( &T3 ); mbedtls_mpi_free( &T4 );
    mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &Z );

    return( ret );
#endif /* !defined(MBEDTLS_ECP_NO_FALLBACK) || !defined(MBEDTLS_ECP_ADD_MIXED_ALT) */
}


/*
 * Check and define parameters used by the comb method (see below for details)
 */
#if MBEDTLS_ECP_WINDOW_SIZE < 2 || MBEDTLS_ECP_WINDOW_SIZE > 7
#error "MBEDTLS_ECP_WINDOW_SIZE out of bounds"
#endif

/* d = ceil( n / w ) */
#define COMB_MAX_D      ( MBEDTLS_ECP_MAX_BITS + 1 ) / 2

/* number of precomputed points */
#define COMB_MAX_PRE    ( 1 << ( MBEDTLS_ECP_WINDOW_SIZE - 1 ) )

/*
 * Compute the representation of m that will be used with our comb method.
 *
 * The basic comb method is described in GECC 3.44 for example. We use a
 * modified version that provides resistance to SPA by avoiding zero
 * digits in the representation as in [3]. We modify the method further by
 * requiring that all K_i be odd, which has the small cost that our
 * representation uses one more K_i, due to carries, but saves on the size of
 * the precomputed table.
 *
 * Summary of the comb method and its modifications:
 *
 * - The goal is to compute m*P for some w*d-bit integer m.
 *
 * - The basic comb method splits m into the w-bit integers
 *   x[0] .. x[d-1] where x[i] consists of the bits in m whose
 *   index has residue i modulo d, and computes m * P as
 *   S[x[0]] + 2 * S[x[1]] + .. + 2^(d-1) S[x[d-1]], where
 *   S[i_{w-1} .. i_0] := i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + i_0 P.
 *
 * - If it happens that, say, x[i+1]=0 (=> S[x[i+1]]=0), one can replace the sum by
 *    .. + 2^{i-1} S[x[i-1]] - 2^i S[x[i]] + 2^{i+1} S[x[i]] + 2^{i+2} S[x[i+2]] ..,
 *   thereby successively converting it into a form where all summands
 *   are nonzero, at the cost of negative summands. This is the basic idea of [3].
 *
 * - More generally, even if x[i+1] != 0, we can first transform the sum as
 *   .. - 2^i S[x[i]] + 2^{i+1} ( S[x[i]] + S[x[i+1]] ) + 2^{i+2} S[x[i+2]] ..,
 *   and then replace S[x[i]] + S[x[i+1]] = S[x[i] ^ x[i+1]] + 2 S[x[i] & x[i+1]].
 *   Performing and iterating this procedure for those x[i] that are even
 *   (keeping track of carry), we can transform the original sum into one of the form
 *   S[x'[0]] +- 2 S[x'[1]] +- .. +- 2^{d-1} S[x'[d-1]] + 2^d S[x'[d]]
 *   with all x'[i] odd. It is therefore only necessary to know S at odd indices,
 *   which is why we are only computing half of it in the first place in
 *   ecp_precompute_comb and accessing it with index abs(i) / 2 in ecp_select_comb.
 *
 * - For the sake of compactness, only the seven low-order bits of x[i]
 *   are used to represent its absolute value (K_i in the paper), and the msb
 *   of x[i] encodes the sign (s_i in the paper): it is set if and only if
 *   if s_i == -1;
 *
 * Calling conventions:
 * - x is an array of size d + 1
 * - w is the size, ie number of teeth, of the comb, and must be between
 *   2 and 7 (in practice, between 2 and MBEDTLS_ECP_WINDOW_SIZE)
 * - m is the MPI, expected to be odd and such that bitlength(m) <= w * d
 *   (the result will be incorrect if these assumptions are not satisfied)
 */
/* to be added later */


 
/*
 * Precompute points for the adapted comb method
 *
 * Assumption: T must be able to hold 2^{w - 1} elements.
 *
 * Operation: If i = i_{w-1} ... i_1 is the binary representation of i,
 *            sets T[i] = i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + P.
 *
 * Cost: d(w-1) D + (2^{w-1} - 1) A + 1 N(w-1) + 1 N(2^{w-1} - 1)
 *
 * Note: Even comb values (those where P would be omitted from the
 *       sum defining T[i] above) are not needed in our adaption
 *       the comb method. See ecp_comb_recode_core().
 *
 * This function currently works in four steps:
 * (1) [dbl]      Computation of intermediate T[i] for 2-power values of i
 * (2) [norm_dbl] Normalization of coordinates of these T[i]
 * (3) [add]      Computation of all T[i]
 * (4) [norm_add] Normalization of all T[i]
 *
 * Step 1 can be interrupted but not the others; together with the final
 * coordinate normalization they are the largest steps done at once, depending
 * on the window size. Here are operation counts for P-256:
 *
 * step     (2)     (3)     (4)
 * w = 5    142     165     208
 * w = 4    136      77     160
 * w = 3    130      33     136
 * w = 2    124      11     124
 *
 * So if ECC operations are blocking for too long even with a low max_ops
 * value, it's useful to set MBEDTLS_ECP_WINDOW_SIZE to a lower value in order
 * to minimize maximum blocking time.
 */
int ecp_precompute_comb_copy( const mbedtls_ecp_group *grp,
                         mbedtls_ecp_point T[], const mbedtls_ecp_point *P,
                         unsigned char w, size_t d )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char i;
    size_t j = 0;
    const unsigned char T_size = 1U << ( w - 1 );
    mbedtls_ecp_point *cur, *TT[COMB_MAX_PRE - 1];

    /*
     * Set T[0] = P and
     * T[2^{l-1}] = 2^{dl} P for l = 1 .. w-1 (this is not the final value)
     */
    MBEDTLS_MPI_CHK( mbedtls_ecp_copy( &T[0], P ) );

    for(j = 0 ; j < d * ( w - 1 ); j++ )
    {
        i = 1U << ( j / d );
        cur = T + i;

        if( j % d == 0 )
            MBEDTLS_MPI_CHK( mbedtls_ecp_copy( cur, T + ( i >> 1 ) ) );

        MBEDTLS_MPI_CHK( ecp_double_jac( grp, cur, cur ) );
    }

    /*
     * Normalize current elements in T. As T has holes,
     * use an auxiliary array of pointers to elements in T.
     */
    j = 0;
    for( i = 1; i < T_size; i <<= 1 )
        TT[j++] = T + i;

    MBEDTLS_MPI_CHK( ecp_normalize_jac_many( grp, TT, j ) );

    /*
     * Compute the remaining ones using the minimal number of additions
     * Be careful to update T[2^l] only after using it!
     */
    for( i = 1; i < T_size; i <<= 1 )
    {
        j = i;
        while( j-- )
            MBEDTLS_MPI_CHK( ecp_add_mixed( grp, &T[i + j], &T[j], &T[i] ) );
    }

    /*
     * Normalize final elements in T. Even though there are no holes now, we
     * still need the auxiliary array for homogeneity with the previous
     * call. Also, skip T[0] which is already normalised, being a copy of P.
     */
    for( j = 0; j + 1 < T_size; j++ )
        TT[j] = T + j + 1;

    MBEDTLS_MPI_CHK( ecp_normalize_jac_many( grp, TT, j ) );

cleanup:

    return( ret );
}

/*
 * Select precomputed point: R = sign(i) * T[ abs(i) / 2 ]
 *
 * See ecp_comb_recode_core() for background
 */
int ecp_select_comb_copy( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                     const mbedtls_ecp_point T[], unsigned char T_size,
                     unsigned char i )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char ii, j;

    /* Ignore the "sign" bit and scale down */
    ii =  ( i & 0x7Fu ) >> 1;

    /* Read the whole table to thwart cache-based timing attacks */
    for( j = 0; j < T_size; j++ )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &R->X, &T[j].X, j == ii ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &R->Y, &T[j].Y, j == ii ) );
    }

    /* Safely invert result if i is "negative" */
    MBEDTLS_MPI_CHK( ecp_safe_invert_jac( grp, R, i >> 7 ) );

cleanup:
    return( ret );
}


#endif /* !MBEDTLS_ECP_ALT */
 
