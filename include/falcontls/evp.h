#ifndef __FC_EVP_H__
#define __FC_EVP_H__

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

#ifdef FC_OPENSSL
#include <openssl/evp.h>

#define FC_EVP_PKEY_free EVP_PKEY_free
#endif

#endif
