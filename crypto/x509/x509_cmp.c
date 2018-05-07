
#include <falcontls/types.h>
#include <falcontls/x509.h>
#include <fc_log.h>

#include "internal/x509.h"

#include <openssl/evp.h>
#include <openssl/x509.h>


FC_EVP_PKEY *
FC_X509_get0_pubkey(const FC_X509 *x)
{
    return (FC_EVP_PKEY *)X509_get_pubkey((X509 *)x);
}
