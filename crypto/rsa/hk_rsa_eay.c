#include <stdio.h>
#include <string.h>

#include <hawktls/hk_bn.h>
#include <hawktls/hk_rsa.h>

#include "internal/rsa.h"
#include "internal/bn.h"

static int RSA_eay_public_encrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);
static int RSA_eay_private_encrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);
static int RSA_eay_public_decrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);
static int RSA_eay_private_decrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);
static int RSA_eay_mod_exp(HK_BIGNUM *r0, const HK_BIGNUM *i, RSA *rsa, BN_CTX *ctx);
static int RSA_eay_init(RSA *rsa);
static int RSA_eay_finish(RSA *rsa);

static RSA_METHOD rsa_pkcs1_eay_meth = {
	.name = "Eric Young's PKCS#1 RSA",
	.rsa_pub_enc = RSA_eay_public_encrypt,
	.rsa_pub_dec = RSA_eay_public_decrypt, /* signature verification */
	.rsa_priv_enc = RSA_eay_private_encrypt, /* signing */
	.rsa_priv_dec = RSA_eay_private_decrypt,
	.rsa_mod_exp = RSA_eay_mod_exp,
	.bn_mod_exp = BN_mod_exp_mont_ct, /* XXX probably we should not use Montgomery if  e == 3 */
	.init = RSA_eay_init,
	.finish = RSA_eay_finish,
};

const RSA_METHOD *
RSA_PKCS1_SSLeay(void)
{
	return &rsa_pkcs1_eay_meth;
}

static int
RSA_eay_public_encrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
	HK_BIGNUM *f, *ret;
	int i, j, k, num = 0, r = -1;
	unsigned char *buf = NULL;
	BN_CTX *ctx = NULL;

	if (BN_num_bits(rsa->n) > OPENSSL_RSA_MAX_MODULUS_BITS) {
		RSAerror(RSA_R_MODULUS_TOO_LARGE);
		return -1;
	}

	if (BN_ucmp(rsa->n, rsa->e) <= 0) {
		RSAerror(RSA_R_BAD_E_VALUE);
		return -1;
	}

	/* for large moduli, enforce exponent limit */
	if (BN_num_bits(rsa->n) > OPENSSL_RSA_SMALL_MODULUS_BITS) {
		if (BN_num_bits(rsa->e) > OPENSSL_RSA_MAX_PUBEXP_BITS) {
			RSAerror(RSA_R_BAD_E_VALUE);
			return -1;
		}
	}

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;

	BN_CTX_start(ctx);
	f = BN_CTX_get(ctx);
	ret = BN_CTX_get(ctx);
	num = BN_num_bytes(rsa->n);
	buf = malloc(num);

	if (f == NULL || ret == NULL || buf == NULL) {
		RSAerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}

	switch (padding) {
	case RSA_PKCS1_PADDING:
		i = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
		break;
#ifndef OPENSSL_NO_SHA
	case RSA_PKCS1_OAEP_PADDING:
		i = RSA_padding_add_PKCS1_OAEP(buf, num, from, flen, NULL, 0);
		break;
#endif
	case RSA_SSLV23_PADDING:
		i = RSA_padding_add_SSLv23(buf, num, from, flen);
		break;
	case RSA_NO_PADDING:
		i = RSA_padding_add_none(buf, num, from, flen);
		break;
	default:
		RSAerror(RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
	}
	if (i <= 0)
		goto err;

	if (BN_bin2bn(buf, num, f) == NULL)
		goto err;

	if (BN_ucmp(f, rsa->n) >= 0) {
		/* usually the padding functions would catch this */
		RSAerror(RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
	}

	if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
		if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n,
		    CRYPTO_LOCK_RSA, rsa->n, ctx))
			goto err;

	if (!rsa->meth->bn_mod_exp(ret, f, rsa->e, rsa->n, ctx,
	    rsa->_method_mod_n))
		goto err;

	/* put in leading 0 bytes if the number is less than the
	 * length of the modulus */
	j = BN_num_bytes(ret);
	i = BN_bn2bin(ret, &(to[num - j]));
	for (k = 0; k < num - i; k++)
		to[k] = 0;

	r = num;
err:
	if (ctx != NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	freezero(buf, num);
	return r;
}

static BN_BLINDING *
rsa_get_blinding(RSA *rsa, int *local, BN_CTX *ctx)
{
	BN_BLINDING *ret;
	int got_write_lock = 0;
	CRYPTO_THREADID cur;

	CRYPTO_r_lock(CRYPTO_LOCK_RSA);

	if (rsa->blinding == NULL) {
		CRYPTO_r_unlock(CRYPTO_LOCK_RSA);
		CRYPTO_w_lock(CRYPTO_LOCK_RSA);
		got_write_lock = 1;

		if (rsa->blinding == NULL)
			rsa->blinding = RSA_setup_blinding(rsa, ctx);
	}

	ret = rsa->blinding;
	if (ret == NULL)
		goto err;

	CRYPTO_THREADID_current(&cur);
	if (!CRYPTO_THREADID_cmp(&cur, BN_BLINDING_thread_id(ret))) {
		/* rsa->blinding is ours! */
		*local = 1;
	} else {
		/* resort to rsa->mt_blinding instead */
		/*
		 * Instruct rsa_blinding_convert(), rsa_blinding_invert()
		 * that the BN_BLINDING is shared, meaning that accesses
		 * require locks, and that the blinding factor must be
		 * stored outside the BN_BLINDING
		 */
		*local = 0;

		if (rsa->mt_blinding == NULL) {
			if (!got_write_lock) {
				CRYPTO_r_unlock(CRYPTO_LOCK_RSA);
				CRYPTO_w_lock(CRYPTO_LOCK_RSA);
				got_write_lock = 1;
			}

			if (rsa->mt_blinding == NULL)
				rsa->mt_blinding = RSA_setup_blinding(rsa, ctx);
		}
		ret = rsa->mt_blinding;
	}

err:
	if (got_write_lock)
		CRYPTO_w_unlock(CRYPTO_LOCK_RSA);
	else
		CRYPTO_r_unlock(CRYPTO_LOCK_RSA);
	return ret;
}

static int
rsa_blinding_convert(BN_BLINDING *b, HK_BIGNUM *f, HK_BIGNUM *unblind, BN_CTX *ctx)
{
	if (unblind == NULL)
		/*
		 * Local blinding: store the unblinding factor
		 * in BN_BLINDING.
		 */
		return BN_BLINDING_convert_ex(f, NULL, b, ctx);
	else {
		/*
		 * Shared blinding: store the unblinding factor
		 * outside BN_BLINDING.
		 */
		int ret;
		CRYPTO_w_lock(CRYPTO_LOCK_RSA_BLINDING);
		ret = BN_BLINDING_convert_ex(f, unblind, b, ctx);
		CRYPTO_w_unlock(CRYPTO_LOCK_RSA_BLINDING);
		return ret;
	}
}

static int
rsa_blinding_invert(BN_BLINDING *b, HK_BIGNUM *f, HK_BIGNUM *unblind, BN_CTX *ctx)
{
	/*
	 * For local blinding, unblind is set to NULL, and BN_BLINDING_invert_ex
	 * will use the unblinding factor stored in BN_BLINDING.
	 * If BN_BLINDING is shared between threads, unblind must be non-null:
	 * BN_BLINDING_invert_ex will then use the local unblinding factor,
	 * and will only read the modulus from BN_BLINDING.
	 * In both cases it's safe to access the blinding without a lock.
	 */
	return BN_BLINDING_invert_ex(f, unblind, b, ctx);
}

/* signing */
static int
RSA_eay_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
	HK_BIGNUM *f, *ret, *res;
	int i, j, k, num = 0, r = -1;
	unsigned char *buf = NULL;
	BN_CTX *ctx = NULL;
	int local_blinding = 0;
	/*
	 * Used only if the blinding structure is shared. A non-NULL unblind
	 * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
	 * the unblinding factor outside the blinding structure.
	 */
	HK_BIGNUM *unblind = NULL;
	BN_BLINDING *blinding = NULL;

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;

	BN_CTX_start(ctx);
	f = BN_CTX_get(ctx);
	ret = BN_CTX_get(ctx);
	num = BN_num_bytes(rsa->n);
	buf = malloc(num);

	if (f == NULL || ret == NULL || buf == NULL) {
		RSAerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}

	switch (padding) {
	case RSA_PKCS1_PADDING:
		i = RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
		break;
	case RSA_X931_PADDING:
		i = RSA_padding_add_X931(buf, num, from, flen);
		break;
	case RSA_NO_PADDING:
		i = RSA_padding_add_none(buf, num, from, flen);
		break;
	case RSA_SSLV23_PADDING:
	default:
		RSAerror(RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
	}
	if (i <= 0)
		goto err;

	if (BN_bin2bn(buf, num, f) == NULL)
		goto err;

	if (BN_ucmp(f, rsa->n) >= 0) {
		/* usually the padding functions would catch this */
		RSAerror(RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
	}

	if (!(rsa->flags & RSA_FLAG_NO_BLINDING)) {
		blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
		if (blinding == NULL) {
			RSAerror(ERR_R_INTERNAL_ERROR);
			goto err;
		}
	}

	if (blinding != NULL) {
		if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL)) {
			RSAerror(ERR_R_MALLOC_FAILURE);
			goto err;
		}
		if (!rsa_blinding_convert(blinding, f, unblind, ctx))
			goto err;
	}

	if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
	    (rsa->p != NULL && rsa->q != NULL && rsa->dmp1 != NULL &&
	    rsa->dmq1 != NULL && rsa->iqmp != NULL)) {
		if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
			goto err;
	} else {
		HK_BIGNUM d;

		BN_init(&d);
		BN_with_flags(&d, rsa->d, BN_FLG_CONSTTIME);

		if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n,
			    CRYPTO_LOCK_RSA, rsa->n, ctx))
				goto err;

		if (!rsa->meth->bn_mod_exp(ret, f, &d, rsa->n, ctx,
		    rsa->_method_mod_n)) {
			goto err;
		}
	}

	if (blinding)
		if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
			goto err;

	if (padding == RSA_X931_PADDING) {
		BN_sub(f, rsa->n, ret);
		if (BN_cmp(ret, f) > 0)
			res = f;
		else
			res = ret;
	} else
		res = ret;

	/* put in leading 0 bytes if the number is less than the
	 * length of the modulus */
	j = BN_num_bytes(res);
	i = BN_bn2bin(res, &(to[num - j]));
	for (k = 0; k < num - i; k++)
		to[k] = 0;

	r = num;
err:
	if (ctx != NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	freezero(buf, num);
	return r;
}

static int
RSA_eay_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
	HK_BIGNUM *f, *ret;
	int j, num = 0, r = -1;
	unsigned char *p;
	unsigned char *buf = NULL;
	BN_CTX *ctx = NULL;
	int local_blinding = 0;
	/*
	 * Used only if the blinding structure is shared. A non-NULL unblind
	 * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
	 * the unblinding factor outside the blinding structure.
	 */
	HK_BIGNUM *unblind = NULL;
	BN_BLINDING *blinding = NULL;

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;

	BN_CTX_start(ctx);
	f = BN_CTX_get(ctx);
	ret = BN_CTX_get(ctx);
	num = BN_num_bytes(rsa->n);
	buf = malloc(num);

	if (!f || !ret || !buf) {
		RSAerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/* This check was for equality but PGP does evil things
	 * and chops off the top '0' bytes */
	if (flen > num) {
		RSAerror(RSA_R_DATA_GREATER_THAN_MOD_LEN);
		goto err;
	}

	/* make data into a big number */
	if (BN_bin2bn(from, (int)flen, f) == NULL)
		goto err;

	if (BN_ucmp(f, rsa->n) >= 0) {
		RSAerror(RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
	}

	if (!(rsa->flags & RSA_FLAG_NO_BLINDING)) {
		blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
		if (blinding == NULL) {
			RSAerror(ERR_R_INTERNAL_ERROR);
			goto err;
		}
	}

	if (blinding != NULL) {
		if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL)) {
			RSAerror(ERR_R_MALLOC_FAILURE);
			goto err;
		}
		if (!rsa_blinding_convert(blinding, f, unblind, ctx))
			goto err;
	}

	/* do the decrypt */
	if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
	    (rsa->p != NULL && rsa->q != NULL && rsa->dmp1 != NULL &&
	    rsa->dmq1 != NULL && rsa->iqmp != NULL)) {
		if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
			goto err;
	} else {
		HK_BIGNUM d;

		BN_init(&d);
		BN_with_flags(&d, rsa->d, BN_FLG_CONSTTIME);

		if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n,
			    CRYPTO_LOCK_RSA, rsa->n, ctx))
				goto err;

		if (!rsa->meth->bn_mod_exp(ret, f, &d, rsa->n, ctx,
		    rsa->_method_mod_n)) {
			goto err;
		}
	}

	if (blinding)
		if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
			goto err;

	p = buf;
	j = BN_bn2bin(ret, p); /* j is only used with no-padding mode */

	switch (padding) {
	case RSA_PKCS1_PADDING:
		r = RSA_padding_check_PKCS1_type_2(to, num, buf, j, num);
		break;
#ifndef OPENSSL_NO_SHA
	case RSA_PKCS1_OAEP_PADDING:
		r = RSA_padding_check_PKCS1_OAEP(to, num, buf, j, num, NULL, 0);
		break;
#endif
	case RSA_SSLV23_PADDING:
		r = RSA_padding_check_SSLv23(to, num, buf, j, num);
		break;
	case RSA_NO_PADDING:
		r = RSA_padding_check_none(to, num, buf, j, num);
		break;
	default:
		RSAerror(RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
	}
	if (r < 0)
		RSAerror(RSA_R_PADDING_CHECK_FAILED);

err:
	if (ctx != NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	freezero(buf, num);
	return r;
}

/* signature verification */
static int
RSA_eay_public_decrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
	HK_BIGNUM *f, *ret;
	int i, num = 0, r = -1;
	unsigned char *p;
	unsigned char *buf = NULL;
	BN_CTX *ctx = NULL;

	if (BN_num_bits(rsa->n) > OPENSSL_RSA_MAX_MODULUS_BITS) {
		RSAerror(RSA_R_MODULUS_TOO_LARGE);
		return -1;
	}

	if (BN_ucmp(rsa->n, rsa->e) <= 0) {
		RSAerror(RSA_R_BAD_E_VALUE);
		return -1;
	}

	/* for large moduli, enforce exponent limit */
	if (BN_num_bits(rsa->n) > OPENSSL_RSA_SMALL_MODULUS_BITS) {
		if (BN_num_bits(rsa->e) > OPENSSL_RSA_MAX_PUBEXP_BITS) {
			RSAerror(RSA_R_BAD_E_VALUE);
			return -1;
		}
	}

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;

	BN_CTX_start(ctx);
	f = BN_CTX_get(ctx);
	ret = BN_CTX_get(ctx);
	num = BN_num_bytes(rsa->n);
	buf = malloc(num);

	if (!f || !ret || !buf) {
		RSAerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/* This check was for equality but PGP does evil things
	 * and chops off the top '0' bytes */
	if (flen > num) {
		RSAerror(RSA_R_DATA_GREATER_THAN_MOD_LEN);
		goto err;
	}

	if (BN_bin2bn(from, flen, f) == NULL)
		goto err;

	if (BN_ucmp(f, rsa->n) >= 0) {
		RSAerror(RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
		goto err;
	}

	if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
		if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n,
		    CRYPTO_LOCK_RSA, rsa->n, ctx))
			goto err;

	if (!rsa->meth->bn_mod_exp(ret, f, rsa->e, rsa->n, ctx,
	    rsa->_method_mod_n))
		goto err;

	if (padding == RSA_X931_PADDING && (ret->d[0] & 0xf) != 12)
		if (!BN_sub(ret, rsa->n, ret))
			goto err;

	p = buf;
	i = BN_bn2bin(ret, p);

	switch (padding) {
	case RSA_PKCS1_PADDING:
		r = RSA_padding_check_PKCS1_type_1(to, num, buf, i, num);
		break;
	case RSA_X931_PADDING:
		r = RSA_padding_check_X931(to, num, buf, i, num);
		break;
	case RSA_NO_PADDING:
		r = RSA_padding_check_none(to, num, buf, i, num);
		break;
	default:
		RSAerror(RSA_R_UNKNOWN_PADDING_TYPE);
		goto err;
	}
	if (r < 0)
		RSAerror(RSA_R_PADDING_CHECK_FAILED);

err:
	if (ctx != NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	freezero(buf, num);
	return r;
}

static int
RSA_eay_mod_exp(HK_BIGNUM *r0, const HK_BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
	HK_BIGNUM *r1, *m1, *vrfy;
	HK_BIGNUM dmp1, dmq1, c, pr1;
	int ret = 0;

	BN_CTX_start(ctx);
	r1 = BN_CTX_get(ctx);
	m1 = BN_CTX_get(ctx);
	vrfy = BN_CTX_get(ctx);
	if (r1 == NULL || m1 == NULL || vrfy == NULL) {
		RSAerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}

	{
		HK_BIGNUM p, q;

		/*
		 * Make sure BN_mod_inverse in Montgomery intialization uses the
		 * BN_FLG_CONSTTIME flag
		 */
		BN_init(&p);
		BN_init(&q);
		BN_with_flags(&p, rsa->p, BN_FLG_CONSTTIME);
		BN_with_flags(&q, rsa->q, BN_FLG_CONSTTIME);

		if (rsa->flags & RSA_FLAG_CACHE_PRIVATE) {
			if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_p,
			     CRYPTO_LOCK_RSA, &p, ctx) ||
			    !BN_MONT_CTX_set_locked(&rsa->_method_mod_q,
			     CRYPTO_LOCK_RSA, &q, ctx)) {
				goto err;
			}
		}
	}

	if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
		if (!BN_MONT_CTX_set_locked(&rsa->_method_mod_n,
		    CRYPTO_LOCK_RSA, rsa->n, ctx))
			goto err;

	/* compute I mod q */
	BN_init(&c);
	BN_with_flags(&c, I, BN_FLG_CONSTTIME);

	if (!BN_mod_ct(r1, &c, rsa->q, ctx))
		goto err;

	/* compute r1^dmq1 mod q */
	BN_init(&dmq1);
	BN_with_flags(&dmq1, rsa->dmq1, BN_FLG_CONSTTIME);

	if (!rsa->meth->bn_mod_exp(m1, r1, &dmq1, rsa->q, ctx,
	    rsa->_method_mod_q))
		goto err;

	/* compute I mod p */
	BN_with_flags(&c, I, BN_FLG_CONSTTIME);

	if (!BN_mod_ct(r1, &c, rsa->p, ctx))
		goto err;

	/* compute r1^dmp1 mod p */
	BN_init(&dmp1);
	BN_with_flags(&dmp1, rsa->dmp1, BN_FLG_CONSTTIME);

	if (!rsa->meth->bn_mod_exp(r0, r1, &dmp1, rsa->p, ctx,
	    rsa->_method_mod_p))
		goto err;

	if (!BN_sub(r0, r0, m1))
		goto err;

	/*
	 * This will help stop the size of r0 increasing, which does
	 * affect the multiply if it optimised for a power of 2 size
	 */
	if (BN_is_negative(r0))
		if (!hk_bn_uadd(r0, r0, rsa->p))
			goto err;

	if (!BN_mul(r1, r0, rsa->iqmp, ctx))
		goto err;

	/* Turn BN_FLG_CONSTTIME flag on before division operation */
	BN_init(&pr1);
	BN_with_flags(&pr1, r1, BN_FLG_CONSTTIME);

	if (!BN_mod_ct(r0, &pr1, rsa->p, ctx))
		goto err;

	/*
	 * If p < q it is occasionally possible for the correction of
	 * adding 'p' if r0 is negative above to leave the result still
	 * negative. This can break the private key operations: the following
	 * second correction should *always* correct this rare occurrence.
	 * This will *never* happen with OpenSSL generated keys because
	 * they ensure p > q [steve]
	 */
	if (BN_is_negative(r0))
		if (!hk_bn_uadd(r0, r0, rsa->p))
			goto err;
	if (!BN_mul(r1, r0, rsa->q, ctx))
		goto err;
	if (!hk_bn_uadd(r0, r1, m1))
		goto err;

	if (rsa->e && rsa->n) {
		if (!rsa->meth->bn_mod_exp(vrfy, r0, rsa->e, rsa->n, ctx,
		    rsa->_method_mod_n))
			goto err;
		/*
		 * If 'I' was greater than (or equal to) rsa->n, the operation
		 * will be equivalent to using 'I mod n'. However, the result of
		 * the verify will *always* be less than 'n' so we don't check
		 * for absolute equality, just congruency.
		 */
		if (!BN_sub(vrfy, vrfy, I))
			goto err;
		if (!BN_mod_ct(vrfy, vrfy, rsa->n, ctx))
			goto err;
		if (BN_is_negative(vrfy))
			if (!hk_bn_uadd(vrfy, vrfy, rsa->n))
				goto err;
		if (!BN_is_zero(vrfy)) {
			/*
			 * 'I' and 'vrfy' aren't congruent mod n. Don't leak
			 * miscalculated CRT output, just do a raw (slower)
			 * mod_exp and return that instead.
			 */
			HK_BIGNUM d;

			BN_init(&d);
			BN_with_flags(&d, rsa->d, BN_FLG_CONSTTIME);

			if (!rsa->meth->bn_mod_exp(r0, I, &d, rsa->n, ctx,
			    rsa->_method_mod_n)) {
				goto err;
			}
		}
	}
	ret = 1;
err:
	BN_CTX_end(ctx);
	return ret;
}

static int
RSA_eay_init(RSA *rsa)
{
	rsa->flags |= RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE;
	return 1;
}

static int
RSA_eay_finish(RSA *rsa)
{
	BN_MONT_CTX_free(rsa->_method_mod_n);
	BN_MONT_CTX_free(rsa->_method_mod_p);
	BN_MONT_CTX_free(rsa->_method_mod_q);

	return 1;
}
