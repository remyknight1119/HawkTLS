#ifndef __FC_TYPES_H__
#define __FC_TYPES_H__

#include <stdio.h>
#include <stdbool.h>

typedef unsigned long           fc_ulong;
typedef unsigned long long      fc_u64;
typedef unsigned int            fc_u32;
typedef unsigned short          fc_u16;
typedef unsigned char           fc_u8;

typedef long                    fc_long;
typedef long long               fc_s64;
typedef int                     fc_s32;
typedef short                   fc_s16;
typedef char                    fc_s8;


typedef unsigned long FC_BN_ULONG;
typedef struct _fc_bn_t fc_bn_t;
typedef fc_bn_t FC_BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct bn_gencb_st BN_GENCB;

typedef struct rsa_st RSA;
typedef struct rsa_meth_st RSA_METHOD;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;

typedef struct crypto_ex_data_st CRYPTO_EX_DATA;

#endif
