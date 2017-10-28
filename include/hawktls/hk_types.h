#ifndef __HK_TYPES_H__
#define __HK_TYPES_H__

typedef unsigned long HK_BN_ULONG;
typedef struct _hk_bn_t hk_bn_t;
typedef hk_bn_t HK_BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct bn_gencb_st BN_GENCB;

typedef struct rsa_st RSA;
typedef struct rsa_meth_st RSA_METHOD;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;

typedef struct crypto_ex_data_st CRYPTO_EX_DATA;

#endif
