
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

FC_EVP_PKEY *
FC_EVP_PKEY_new(void)
{
    return (FC_EVP_PKEY *)EVP_PKEY_new();
}

void
FC_EVP_PKEY_free(FC_EVP_PKEY *pkey)
{
    EVP_PKEY_free((EVP_PKEY *)pkey);
}

int
FC_EVP_PKEY_missing_parameters(const FC_EVP_PKEY *pkey)
{
    return EVP_PKEY_missing_parameters((const EVP_PKEY *)pkey);
}
