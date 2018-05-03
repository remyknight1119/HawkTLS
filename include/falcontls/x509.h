#ifndef __FC_X509_H__
#define __FC_X509_H__

#include <stdint.h>

#include <falcontls/safestack.h>

#define FC_X509_FILETYPE_PEM    1
#define FC_X509_FILETYPE_ASN1   2

FC_DEFINE_STACK_OF(FC_X509)

extern int FC_X509_check_private_key(const FC_X509 *x, const FC_EVP_PKEY *k);
extern void FC_X509_free(FC_X509 *x);
extern FC_EVP_PKEY *FC_X509_get0_pubkey(const FC_X509 *x);

#endif
