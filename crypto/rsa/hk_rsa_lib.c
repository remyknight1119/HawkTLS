#include <stdlib.h>

#include <hawktls/hk_rsa.h>
#include <hawktls/hk_bn.h>
#include <hawktls/hk_crypto.h>
#include "internal/rsa.h"

static const RSA_METHOD *default_RSA_meth = NULL;

RSA *
RSA_new(void)
{
	return RSA_new_method(NULL);
}

void
RSA_set_default_method(const RSA_METHOD *meth)
{
	default_RSA_meth = meth;
}

const RSA_METHOD *
RSA_get_default_method(void)
{
	if (default_RSA_meth == NULL)
		default_RSA_meth = RSA_PKCS1_SSLeay();

	return default_RSA_meth;
}

const RSA_METHOD *
RSA_get_method(const RSA *rsa)
{
	return rsa->meth;
}

int
RSA_set_method(RSA *rsa, const RSA_METHOD *meth)
{
	/*
	 * NB: The caller is specifically setting a method, so it's not up to us
	 * to deal with which ENGINE it comes from.
	 */
	const RSA_METHOD *mtmp;

	mtmp = rsa->meth;
	if (mtmp->finish)
		mtmp->finish(rsa);
	rsa->meth = meth;
	if (meth->init)
		meth->init(rsa);
	return 1;
}

RSA *
RSA_new_method(void *engine)
{
	RSA *ret;

	ret = malloc(sizeof(RSA));
	if (ret == NULL) {
		return NULL;
	}

	ret->meth = RSA_get_default_method();

	ret->version = 0;
	ret->n = NULL;
	ret->e = NULL;
	ret->d = NULL;
	ret->p = NULL;
	ret->q = NULL;
	ret->dmp1 = NULL;
	ret->dmq1 = NULL;
	ret->iqmp = NULL;
	ret->references = 1;
	ret->_method_mod_n = NULL;
	ret->_method_mod_p = NULL;
	ret->_method_mod_q = NULL;
	ret->blinding = NULL;
	ret->mt_blinding = NULL;
	ret->flags = ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
	if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data)) {
		free(ret);
		return NULL;
	}

	if (ret->meth->init != NULL && !ret->meth->init(ret)) {
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data);
		free(ret);
		ret = NULL;
	}
	return ret;
}


void
RSA_free(RSA *r)
{
	int i;

	if (r == NULL)
		return;

	i = HK_CRYPTO_add(&r->references, -1, HK_CRYPTO_LOCK_RSA);
	if (i > 0)
		return;

	if (r->meth->finish)
		r->meth->finish(r);
#if 0
	if (r->engine)
		ENGINE_finish(r->engine);
#endif

	//CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, r, &r->ex_data);

	hk_bn_clear_free(r->n);
	hk_bn_clear_free(r->e);
	hk_bn_clear_free(r->d);
	hk_bn_clear_free(r->p);
	hk_bn_clear_free(r->q);
	hk_bn_clear_free(r->dmp1);
	hk_bn_clear_free(r->dmq1);
	hk_bn_clear_free(r->iqmp);
	//BN_BLINDING_free(r->blinding);
	//BN_BLINDING_free(r->mt_blinding);
	free(r);
}
