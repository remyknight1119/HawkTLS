
#include <falcontls/asn1t.h>
#include <falcontls/x509.h>

FC_ASN1_SEQUENCE_ref(FC_X509, fc_x509_cb) = {
        FC_ASN1_EMBED(FC_X509, cert_info, FC_X509_CINF),
        FC_ASN1_EMBED(FC_X509, sig_alg, FC_X509_ALGOR),
        FC_ASN1_EMBED(FC_X509, signature, FC_ASN1_BIT_STRING)
} FC_ASN1_SEQUENCE_END_ref(FC_X509, FC_X509)


FC_IMPLEMENT_ASN1_FUNCTIONS(FC_X509)
