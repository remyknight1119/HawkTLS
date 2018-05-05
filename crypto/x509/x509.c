
#include <falcontls/types.h>
#include <falcontls/x509.h>
#include <fc_log.h>

#include "internal/x509.h"

#include <openssl/evp.h>

int
FC_X509_check_private_key(const FC_X509 *x, const FC_EVP_PKEY *k)
{
    return X509_check_private_key((X509 *)x, (EVP_PKEY *)k);
}

FC_EVP_PKEY *
FC_X509_get0_pubkey(const FC_X509 *x)
{
    return (FC_EVP_PKEY *)X509_get_pubkey((X509 *)x);
}

