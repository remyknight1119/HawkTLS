#ifndef __FC_ASN1_H__
#define __FC_ASN1_H__

#include <falcontls/types.h>

typedef struct FC_ASN1_TEMPLATE_st FC_ASN1_TEMPLATE;
typedef struct FC_ASN1_VALUE_st FC_ASN1_VALUE;

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
