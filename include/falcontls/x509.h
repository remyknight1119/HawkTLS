#ifndef __FC_X509_H__
#define __FC_X509_H__

#include <stdint.h>

#include <falcontls/safestack.h>
#include <falcontls/asn1.h>

#define FC_X509_FILETYPE_PEM    1
#define FC_X509_FILETYPE_ASN1   2


FC_DEFINE_STACK_OF(FC_X509)

//FC_DECLARE_ASN1_FUNCTIONS(FC_X509)

extern int FC_X509_check_private_key(const FC_X509 *x, const FC_EVP_PKEY *k);
extern FC_EVP_PKEY *FC_X509_get0_pubkey(const FC_X509 *x);
extern int FC_X509_up_ref(FC_X509 *x);


extern FC_X509 *
d2i_FC_X509(FC_X509 **val, const fc_u8 **in, long len);
void FC_X509_free(FC_X509 *x);

#endif
