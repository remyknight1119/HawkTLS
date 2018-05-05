

#include <falcontls/asn1.h>
#include <falcontls/asn1t.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

int
FC_ASN1_item_ndef_i2d(FC_ASN1_VALUE *val, fc_u8 **out, const FC_ASN1_ITEM *it)
{
    return ASN1_item_ndef_i2d((ASN1_VALUE *)val, out, (const ASN1_ITEM *)it);
}

int
FC_ASN1_item_i2d(FC_ASN1_VALUE *val, fc_u8 **out, const FC_ASN1_ITEM *it)
{
    return ASN1_item_i2d((ASN1_VALUE *)val, out, (const ASN1_ITEM *)it);
}
