
#include <falcontls/pem.h>

#ifdef FC_OPENSSL
#include <openssl/pem.h>

#include "internal/bio.h"

FC_X509 *
FC_PEM_read_bio_X509(FC_BIO *bp, FC_X509 **x, 
            fc_pem_password_cb *cb, void *u)
{
    return (FC_X509 *)PEM_read_bio_X509(bp->b, (X509 **)x, cb, u);
}

FC_EVP_PKEY *
FC_PEM_read_bio_PrivateKey(FC_BIO *bp, FC_EVP_PKEY **x,
            fc_pem_password_cb *cb, void *u)
{
    return (FC_EVP_PKEY *)PEM_read_bio_PrivateKey(bp->b, (EVP_PKEY **)x, cb, u);
}
#endif
