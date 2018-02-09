#ifndef __FC_X509_H__
#define __FC_X509_H__

#include <stdint.h>

#ifdef FC_OPENSSL
#include <openssl/x509.h>
#include <openssl/ssl.h>

#define FC_X509_FILETYPE_PEM    SSL_FILETYPE_PEM
#define FC_X509_FILETYPE_ASN1   SSL_FILETYPE_ASN1
#define FC_X509_get0_pubkey(x)  X509_get_pubkey((X509 *)x)

#define FC_X509_free X509_free
#else
#define FC_X509_FILETYPE_PEM    1
#define FC_X509_FILETYPE_ASN1   2


#endif

#endif
