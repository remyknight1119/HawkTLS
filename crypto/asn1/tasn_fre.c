

#include <falcontls/asn1.h>
#include <falcontls/asn1t.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

void
FC_ASN1_item_free(FC_ASN1_VALUE *val, const FC_ASN1_ITEM *it)
{
    ASN1_item_free((ASN1_VALUE *)val, (const ASN1_ITEM *)it);
}
