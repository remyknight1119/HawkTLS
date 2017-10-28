#ifndef __RSA_H__
#define __RSA_H__

#include <hawktls/hk_types.h>
#include <hawktls/hk_crypto.h>

#define RSAerr(type)

struct rsa_meth_st {
	const char *name;
	int (*rsa_pub_enc)(int flen, const unsigned char *from,
	    unsigned char *to, RSA *rsa, int padding);
	int (*rsa_pub_dec)(int flen, const unsigned char *from,
	    unsigned char *to, RSA *rsa, int padding);
	int (*rsa_priv_enc)(int flen, const unsigned char *from,
	    unsigned char *to, RSA *rsa, int padding);
	int (*rsa_priv_dec)(int flen, const unsigned char *from,
	    unsigned char *to, RSA *rsa, int padding);
	int (*rsa_mod_exp)(HK_BIGNUM *r0, const HK_BIGNUM *I, RSA *rsa,
	    BN_CTX *ctx); /* Can be null */
	int (*bn_mod_exp)(HK_BIGNUM *r, const HK_BIGNUM *a, const HK_BIGNUM *p,
	    const HK_BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx); /* Can be null */
	int (*init)(RSA *rsa);		/* called at new */
	int (*finish)(RSA *rsa);	/* called at free */
	int flags;			/* RSA_METHOD_FLAG_* things */
	char *app_data;			/* may be needed! */
/* New sign and verify functions: some libraries don't allow arbitrary data
 * to be signed/verified: this allows them to be used. Note: for this to work
 * the RSA_public_decrypt() and RSA_private_encrypt() should *NOT* be used
 * RSA_sign(), RSA_verify() should be used instead. Note: for backwards
 * compatibility this functionality is only enabled if the RSA_FLAG_SIGN_VER
 * option is set in 'flags'.
 */
	int (*rsa_sign)(int type, const unsigned char *m, unsigned int m_length,
	    unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
	int (*rsa_verify)(int dtype, const unsigned char *m,
	    unsigned int m_length, const unsigned char *sigbuf,
	    unsigned int siglen, const RSA *rsa);
/* If this callback is NULL, the builtin software RSA key-gen will be used. This
 * is for behavioural compatibility whilst the code gets rewired, but one day
 * it would be nice to assume there are no such things as "builtin software"
 * implementations. */
	int (*rsa_keygen)(RSA *rsa, int bits, HK_BIGNUM *e, BN_GENCB *cb);
};

struct rsa_st {
	long version;
	const RSA_METHOD *meth;
	/* functional reference if 'meth' is ENGINE-provided */
	//ENGINE *engine;
	HK_BIGNUM *n;
	HK_BIGNUM *e;
	HK_BIGNUM *d;
	HK_BIGNUM *p;
	HK_BIGNUM *q;
	HK_BIGNUM *dmp1;
	HK_BIGNUM *dmq1;
	HK_BIGNUM *iqmp;
	/* be careful using this if the RSA structure is shared */
	CRYPTO_EX_DATA ex_data;
	int references;
	int flags;

	/* Used to cache montgomery values */
	BN_MONT_CTX *_method_mod_n;
	BN_MONT_CTX *_method_mod_p;
	BN_MONT_CTX *_method_mod_q;

	/* all HK_BIGNUM values are actually in the following data, if it is not
	 * NULL */
	BN_BLINDING *blinding;
	BN_BLINDING *mt_blinding;
};

extern RSA *RSA_new_method(void *engine);
extern const RSA_METHOD *RSA_PKCS1_SSLeay(void);


#endif
