

#include <falcontls/dh.h>

#include "dh_locl.h"

#include <openssl/dh.h>

FC_DH *
FC_DH_new(void)
{
    return (FC_DH *)DH_new();
}

void
FC_DH_free(FC_DH *r)
{
    DH_free((DH *)r);
}

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* If the fields p and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.  q may remain NULL.
     */
    if ((dh->p == NULL && p == NULL)
        || (dh->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        BN_free(dh->p);
        dh->p = p;
    }
    if (q != NULL) {
        BN_free(dh->q);
        dh->q = q;
    }
    if (g != NULL) {
        BN_free(dh->g);
        dh->g = g;
    }

    if (q != NULL) {
        dh->length = BN_num_bits(q);
    }

    return 1;
}

int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
    if (pub_key != NULL) {
        BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(dh->priv_key);
        dh->priv_key = priv_key;
    }

    return 1;
}

int DH_check_params(const DH *dh, int *ret)
{
    int ok = 0;
    BIGNUM *tmp = NULL;
    BN_CTX *ctx = NULL;

    *ret = 0;
    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL)
        goto err;

    if (!BN_is_odd(dh->p))
        *ret |= DH_CHECK_P_NOT_PRIME;
    if (BN_is_negative(dh->g) || BN_is_zero(dh->g) || BN_is_one(dh->g))
        *ret |= DH_NOT_SUITABLE_GENERATOR;
    if (BN_copy(tmp, dh->p) == NULL || !BN_sub_word(tmp, 1))
        goto err;
    if (BN_cmp(dh->g, tmp) >= 0)
        *ret |= DH_NOT_SUITABLE_GENERATOR;

    ok = 1;
 err:
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return (ok);
}


int
FC_DH_set0_key(FC_DH *dh, FC_BIGNUM *pub_key, FC_BIGNUM *priv_key)
{
    return DH_set0_key((DH *)dh, (BIGNUM *)pub_key, (BIGNUM *)priv_key);
}

int
FC_DH_set0_pqg(FC_DH *dh, FC_BIGNUM *p, FC_BIGNUM *q, FC_BIGNUM *g)
{
    return DH_set0_pqg((DH *)dh, (BIGNUM *)p, (BIGNUM *)q, (BIGNUM *)g);
}

int
FC_DH_check_params(const FC_DH *dh, int *ret)
{
    return DH_check_params((const DH *)dh, ret);
}
