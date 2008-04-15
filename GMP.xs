/* $Id$
 *
 * Copyright (c) 2008 Daisuke Maki <daisuke@endeworks.jp>
 */

#ifndef __CRYPT_DH_GMP_XS__
#define __CRYPT_DH_GMP_XS__

#include "dh_gmp.h"

static
void DH_mpz_rand_set(mpz_t *v, unsigned int bits)
{
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long) time(NULL));
    mpz_urandomb(*v, state, bits);
    gmp_randclear(state);
}

static inline
char *DH_mpz2sv_str(mpz_t *v)
{
    STRLEN len;
    char *buf, *buf_end;

    /* len is always >= 1, and might be off (greater) by one than real len */
    len = mpz_sizeinbase(*v, 10);
    Newxz(buf, len, char);
    buf_end = buf + len - 1; /* end of storage (-1) */
    mpz_get_str(buf, 10, *v);
    if (*buf_end == 0) {
        Renew(buf, len - 1, char); /* got one shorter than expected */
    }
    return buf;
}

#endif /* __CRYPT_DH_GMP_XS__ */

MODULE = Crypt::DH::GMP       PACKAGE = Crypt::DH::GMP  PREFIX = DH_gmp_ 

PROTOTYPES: DISABLE 

DH_gmp_t *
DH_gmp__xs_new(class, p, g, priv_key = NULL)
        char *class;
        char *p;
        char *g;
        char *priv_key;
    PREINIT:
        DH_gmp_t *ptr;
    CODE:
        Newxz(ptr, 1, DH_gmp_t);

        mpz_init(ptr->pub_key);
        mpz_init_set_str(ptr->p, p, 0);
        mpz_init_set_str(ptr->g, g, 0);
        if (priv_key != NULL && sv_len(ST(3)) > 0) {
            mpz_init_set_str(ptr->priv_key, priv_key, 10);
        } else {
            mpz_init_set_ui(ptr->priv_key, 0);
        } 

        RETVAL = ptr;
    OUTPUT:
        RETVAL

void
DH_gmp_generate_keys(dh)
        DH_gmp_t *dh;
    CODE:
        if (mpz_cmp_ui(dh->priv_key, 0) == 0) {
            mpz_t max;

            /* not initialized, eh? */
            mpz_init(max);
            mpz_sub_ui(max, dh->p, 1);
            do {
                DH_mpz_rand_set(&(dh->priv_key), mpz_sizeinbase(dh->p, 2));
            } while ( mpz_cmp(dh->priv_key, max) > 0 );
        }
            
        mpz_powm( dh->pub_key, dh->g, dh->priv_key, dh->p );

char *
DH_gmp_compute_key(dh, pub_key)
        DH_gmp_t *dh;
        char * pub_key;
    PREINIT:
        DH_mpz_t mpz_ret;
        DH_mpz_t mpz_pub_key;
    CODE:
        mpz_init(mpz_ret);
        mpz_init_set_str(mpz_pub_key, pub_key, 0);
        mpz_powm(mpz_ret, mpz_pub_key, dh->priv_key, dh->p);
        RETVAL = DH_mpz2sv_str(&mpz_ret);
        mpz_clear(mpz_ret);
        mpz_clear(mpz_pub_key);
    OUTPUT:
        RETVAL

char *
DH_gmp_priv_key(dh)
        DH_gmp_t *dh;
    CODE:
        RETVAL = DH_mpz2sv_str(&( dh->priv_key ));
    OUTPUT:
        RETVAL

char *
DH_gmp_pub_key(dh)
        DH_gmp_t *dh;
    CODE:
        RETVAL = DH_mpz2sv_str(&( dh->pub_key ));
    OUTPUT:
        RETVAL

char *
DH_gmp_g(dh, ...)
        DH_gmp_t *dh;
    PREINIT:
        STRLEN n_a;
    CODE:
        RETVAL = DH_mpz2sv_str(&( dh->g ));
        if (items > 1) {
            mpz_init_set_str( dh->g, (char *) SvPV(ST(1), n_a), 0 );
        }
    OUTPUT:
        RETVAL

char *
DH_gmp_p(dh, ...)
        DH_gmp_t *dh;
    PREINIT:
        STRLEN n_a;
    CODE:
        RETVAL = DH_mpz2sv_str(&( dh->p ));
        if (items > 1) {
            mpz_init_set_str( dh->p, (char *) SvPV(ST(1), n_a), 0 );
        }
    OUTPUT:
        RETVAL

void
DESTROY(dh)
        DH_gmp_t *dh;
    CODE:
        mpz_clear(dh->p);
        mpz_clear(dh->g);
        mpz_clear(dh->pub_key);
        mpz_clear(dh->priv_key);
        Safefree(dh);
        
