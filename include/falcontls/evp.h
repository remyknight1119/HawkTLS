#ifndef __FC_EVP_H__
#define __FC_EVP_H__

#include <falcontls/types.h>

#include <openssl/evp.h>

#define FC_EVP_MAX_MD_SIZE              64/* longest known is SHA512 */
#define FC_EVP_MAX_KEY_LENGTH           64
#define FC_EVP_MAX_IV_LENGTH            16
#define FC_EVP_MAX_BLOCK_LENGTH         32

#define FC_EVP_PKEY_RSA             EVP_PKEY_RSA
#define FC_EVP_PKEY_DH              EVP_PKEY_DH
#define FC_EVP_PKEY_EC              EVP_PKEY_EC

/*
 * Cipher handles any and all padding logic as well as finalisation.
 */
#define FC_EVP_CIPH_FLAG_CUSTOM_CIPHER      0x100000
#define FC_EVP_CIPH_FLAG_AEAD_CIPHER        0x200000
#define FC_EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK  0x400000
/* Cipher can handle pipeline operations */
#define FC_EVP_CIPH_FLAG_PIPELINE           0X800000


enum {
    FC_EVP_PKEY_RSA_ENC = 0,
    FC_EVP_PKEY_RSA_SIGN,
    FC_EVP_PKEY_ECC,
    FC_EVP_PKEY_GOST01,
    FC_EVP_PKEY_GOST12_256,
    FC_EVP_PKEY_GOST12_512,
    FC_EVP_PKEY_NUM,
};

#define FC_EVP_MD_CTX_size(e)          FC_EVP_MD_size(FC_EVP_MD_CTX_md(e))
#define FC_EVP_MD_CTX_block_size(e)    FC_EVP_MD_block_size(FC_EVP_MD_CTX_md(e))
#define FC_EVP_MD_CTX_type(e)          FC_EVP_MD_type(FC_EVP_MD_CTX_md(e))

#define FC_EVP_PKEY_assign_RSA(pkey,rsa) \
        FC_EVP_PKEY_assign((pkey), FC_EVP_PKEY_RSA, (char *)(rsa))
#define FC_EVP_PKEY_assign_DH(pkey,dh) \
        FC_EVP_PKEY_assign((pkey), FC_EVP_PKEY_DH, (char *)(dh))
#define FC_EVP_PKEY_assign_EC_KEY(pkey,eckey) \
        FC_EVP_PKEY_assign((pkey), FC_EVP_PKEY_EC, (char *)(eckey))

extern int FC_EVP_PKEY_id(const FC_EVP_PKEY *pkey);
extern FC_EVP_PKEY *FC_EVP_PKEY_new(void);
extern void FC_EVP_PKEY_free(FC_EVP_PKEY *pkey);
extern const FC_EVP_CIPHER *
FC_EVP_CIPHER_CTX_cipher(const FC_EVP_CIPHER_CTX *ctx);
extern int FC_EVP_PKEY_missing_parameters(const FC_EVP_PKEY *pkey);
extern fc_ulong FC_EVP_CIPHER_flags(const FC_EVP_CIPHER *cipher);
extern const FC_EVP_MD *FC_EVP_MD_CTX_md(const FC_EVP_MD_CTX *ctx);
extern int FC_EVP_MD_size(const FC_EVP_MD *md);
extern int FC_EVP_PKEY_assign(FC_EVP_PKEY *pkey, int type, void *key);


#endif
