#ifndef __FC_X509_H__
#define __FC_X509_H__

#include <stdint.h>

#ifdef FC_OPENSSL
#include <openssl/x509.h>

#define FC_X509_FILETYPE_PEM    X509_FILETYPE_PEM
#define FC_X509_FILETYPE_ASN1   X509_FILETYPE_ASN1
#define FC_X509_get0_pubkey(x)  X509_get_pubkey((X509 *)x)
#define FC_X509_check_private_key X509_check_private_key
#define FC_X509_free X509_free
#else
#define FC_X509_FILETYPE_PEM    1
#define FC_X509_FILETYPE_ASN1   2


#endif

#endif
