
#include <falcontls/types.h>
#include <falcontls/evp.h>

#include <openssl/evp.h>

int
FC_EVP_PKEY_id(const FC_EVP_PKEY *pkey)
{
    switch (EVP_PKEY_id((EVP_PKEY *)pkey)) {
        case EVP_PKEY_RSA:
            return FC_EVP_PKEY_RSA_ENC;
        case EVP_PKEY_EC:
            return FC_EVP_PKEY_ECC;
        case NID_id_GostR3410_2001:
            return FC_EVP_PKEY_GOST01;
    }

    return -1;
}

void
FC_EVP_PKEY_free(FC_EVP_PKEY *pkey)
{
    EVP_PKEY_free((EVP_PKEY *)pkey);
}
