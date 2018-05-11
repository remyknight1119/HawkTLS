

#include <falcontls/asn1.h>
#include <falcontls/asn1t.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <fc_log.h>

FC_ASN1_VALUE *
FC_ASN1_item_d2i(FC_ASN1_VALUE **val, const fc_u8 **in, long len,
        const FC_ASN1_ITEM *it)
{
    return (FC_ASN1_VALUE *)ASN1_item_d2i((ASN1_VALUE **)val,
                            (const unsigned char **)in, len,
                            (const ASN1_ITEM *)it);
}

