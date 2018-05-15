#ifndef __FC_DH_H__
#define __FC_DH_H__

#include <falcontls/types.h>

extern FC_DH *FC_DH_new(void);
extern void FC_DH_free(FC_DH *r);
extern int FC_DH_set0_key(FC_DH *dh, FC_BIGNUM *pub_key, FC_BIGNUM *priv_key);
extern int FC_DH_set0_pqg(FC_DH *dh, FC_BIGNUM *p, FC_BIGNUM *q, FC_BIGNUM *g);
extern int FC_DH_check_params(const FC_DH *dh, int *ret);

#endif
