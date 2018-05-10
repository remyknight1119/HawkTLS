#ifndef __FC_ASN1_H__
#define __FC_ASN1_H__

#include <falcontls/types.h>

#define FC_V_ASN1_UNIVERSAL                0x00
#define FC_V_ASN1_APPLICATION              0x40
#define FC_V_ASN1_CONTEXT_SPECIFIC         0x80
#define FC_V_ASN1_PRIVATE                  0xc0

#define FC_V_ASN1_CONSTRUCTED              0x20
#define FC_V_ASN1_PRIMITIVE_TAG            0x1f
#define FC_V_ASN1_PRIMATIVE_TAG            0x1f

#define FC_V_ASN1_APP_CHOOSE               -2/* let the recipient choose */
#define FC_V_ASN1_OTHER                    -3/* used in ASN1_TYPE */
#define FC_V_ASN1_ANY                      -4/* used in ASN1 template code */

#define FC_V_ASN1_UNDEF                    -1
/* ASN.1 tag values */
#define FC_V_ASN1_EOC                      0
#define FC_V_ASN1_BOOLEAN                  1 /**/
#define FC_V_ASN1_INTEGER                  2
#define FC_V_ASN1_BIT_STRING               3
#define FC_V_ASN1_OCTET_STRING             4
#define FC_V_ASN1_NULL                     5
#define FC_V_ASN1_OBJECT                   6
#define FC_V_ASN1_OBJECT_DESCRIPTOR        7
#define FC_V_ASN1_EXTERNAL                 8
#define FC_V_ASN1_REAL                     9
#define FC_V_ASN1_ENUMERATED               10
#define FC_V_ASN1_UTF8STRING               12
#define FC_V_ASN1_SEQUENCE                 16
#define FC_V_ASN1_SET                      17
#define FC_V_ASN1_NUMERICSTRING            18 /**/
#define FC_V_ASN1_PRINTABLESTRING          19
#define FC_V_ASN1_T61STRING                20
#define FC_V_ASN1_TELETEXSTRING            20/* alias */
#define FC_V_ASN1_VIDEOTEXSTRING           21 /**/
#define FC_V_ASN1_IA5STRING                22
#define FC_V_ASN1_UTCTIME                  23
#define FC_V_ASN1_GENERALIZEDTIME          24 /**/
#define FC_V_ASN1_GRAPHICSTRING            25 /**/
#define FC_V_ASN1_ISO64STRING              26 /**/
#define FC_V_ASN1_VISIBLESTRING            26/* alias */
#define FC_V_ASN1_GENERALSTRING            27 /**/
#define FC_V_ASN1_UNIVERSALSTRING          28 /**/
#define FC_V_ASN1_BMPSTRING                30

/*
 * NB the constants below are used internally by ASN1_INTEGER
 * and ASN1_ENUMERATED to indicate the sign. They are *not* on
 * the wire tag values.
 */

#define FC_V_ASN1_NEG                      0x100
#define FC_V_ASN1_NEG_INTEGER              (2 | FC_V_ASN1_NEG)
#define FC_V_ASN1_NEG_ENUMERATED           (10 | FC_V_ASN1_NEG)


typedef struct FC_ASN1_TEMPLATE_t FC_ASN1_TEMPLATE;
typedef struct FC_ASN1_VALUE_t FC_ASN1_VALUE;
typedef const FC_ASN1_ITEM FC_ASN1_ITEM_EXP;

/* Macro to obtain ASN1_ITEM pointer from exported type */
#define FC_ASN1_ITEM_ptr(iptr) (iptr)

/* Macro to include ASN1_ITEM pointer from base type */
#define FC_ASN1_ITEM_ref(iptr) (&(iptr##_it))

#define FC_ASN1_ITEM_rptr(ref) (&(ref##_it))


#define FC_DECLARE_ASN1_ITEM(name) \
        extern const FC_ASN1_ITEM name##_it;

/* Declare ASN1 functions: the implement macro in in asn1t.h */

#define FC_DECLARE_ASN1_FUNCTIONS(type) \
        FC_DECLARE_ASN1_FUNCTIONS_name(type, type)

#define FC_DECLARE_ASN1_ALLOC_FUNCTIONS(type) \
        FC_DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, type)

#define FC_DECLARE_ASN1_FUNCTIONS_name(type, name) \
        FC_DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
        FC_DECLARE_ASN1_ENCODE_FUNCTIONS(type, name, name)

#define FC_DECLARE_ASN1_FUNCTIONS_fname(type, itname, name) \
        FC_DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
        FC_DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name)

#define FC_DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name) \
        type *d2i_##name(type **a, const fc_u8 **in, long len); \
        int i2d_##name(type *a, fc_u8 **out); \
        FC_DECLARE_ASN1_ITEM(itname)

#define FC_DECLARE_ASN1_ENCODE_FUNCTIONS_const(type, name) \
        type *d2i_##name(type **a, const fc_u8 **in, long len); \
        int i2d_##name(const type *a, fc_u8 **out); \
        FC_DECLARE_ASN1_ITEM(name)

#define FC_DECLARE_ASN1_NDEF_FUNCTION(name) \
        int i2d_##name##_NDEF(name *a, fc_u8 **out);

#define FC_DECLARE_ASN1_FUNCTIONS_const(name) \
        FC_DECLARE_ASN1_ALLOC_FUNCTIONS(name) \
        FC_DECLARE_ASN1_ENCODE_FUNCTIONS_const(name, name)

#define FC_DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
        type *name##_new(void); \
        void name##_free(type *a);

extern FC_ASN1_VALUE *FC_ASN1_item_new(const FC_ASN1_ITEM *it);
extern void FC_ASN1_item_free(FC_ASN1_VALUE *val, const FC_ASN1_ITEM *it);
extern FC_ASN1_VALUE *FC_ASN1_item_d2i(FC_ASN1_VALUE **val, const fc_u8 **in,
                            long len, const FC_ASN1_ITEM *it);
extern int FC_ASN1_item_i2d(FC_ASN1_VALUE *val, fc_u8 **out,
                            const FC_ASN1_ITEM *it);
extern int FC_ASN1_item_ndef_i2d(FC_ASN1_VALUE *val, fc_u8 **out,
                            const FC_ASN1_ITEM *it);


#endif
