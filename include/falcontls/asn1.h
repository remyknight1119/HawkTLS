#ifndef __FC_ASN1_H__
#define __FC_ASN1_H__

#include <falcontls/types.h>

typedef struct FC_ASN1_VALUE_st FC_ASN1_VALUE;

#define FC_DECLARE_ASN1_ITEM(name) \
        extern const FC_ASN1_ITEM fc_##name##_it;

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
        type *fc_d2i_##name(type **a, const fc_u8 **in, long len); \
        int fc_i2d_##name(type *a, fc_u8 **out); \
        FC_DECLARE_ASN1_ITEM(itname)

#define FC_DECLARE_ASN1_ENCODE_FUNCTIONS_const(type, name) \
        type *fc_d2i_##name(type **a, const fc_u8 **in, long len); \
        int fc_i2d_##name(const type *a, fc_u8 **out); \
        FC_DECLARE_ASN1_ITEM(name)

#define FC_DECLARE_ASN1_NDEF_FUNCTION(name) \
        int fc_i2d_##name##_NDEF(name *a, fc_u8 **out);

#define FC_DECLARE_ASN1_FUNCTIONS_const(name) \
        FC_DECLARE_ASN1_ALLOC_FUNCTIONS(name) \
        FC_DECLARE_ASN1_ENCODE_FUNCTIONS_const(name, name)

#define FC_DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
        type *fc_##name##_new(void); \
        void fc_##name##_free(type *a);


#endif
