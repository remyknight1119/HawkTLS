

#include <falcontls/asn1.h>
#include <falcontls/asn1t.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

FC_ASN1_VALUE *
FC_ASN1_item_new(const FC_ASN1_ITEM *it)
{
    return (FC_ASN1_VALUE *)ASN1_item_new((const ASN1_ITEM *)it);
}

