#ifndef __FC_EVP_H__
#define __FC_EVP_H__

#include <falcontls/types.h>

#define FC_EVP_MAX_MD_SIZE              64/* longest known is SHA512 */
#define FC_EVP_MAX_KEY_LENGTH           64
#define FC_EVP_MAX_IV_LENGTH            16
#define FC_EVP_MAX_BLOCK_LENGTH         32

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

extern int FC_EVP_PKEY_id(const FC_EVP_PKEY *pkey);
extern void FC_EVP_PKEY_free(FC_EVP_PKEY *pkey);
extern const FC_EVP_CIPHER *
FC_EVP_CIPHER_CTX_cipher(const FC_EVP_CIPHER_CTX *ctx);
extern fc_ulong FC_EVP_CIPHER_flags(const FC_EVP_CIPHER *cipher);

#endif
