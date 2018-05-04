#ifndef __FC_ASN1T_H__
#define __FC_ASN1T_H__

/* Macro to implement standard functions in terms of FC_ASN1_ITEM structures */

#define FC_IMPLEMENT_ASN1_FUNCTIONS(stname) \
        FC_IMPLEMENT_ASN1_FUNCTIONS_fname(stname, stname, stname)

#define FC_IMPLEMENT_ASN1_FUNCTIONS_name(stname, itname) \
        FC_IMPLEMENT_ASN1_FUNCTIONS_fname(stname, itname, itname)

#define FC_IMPLEMENT_ASN1_FUNCTIONS_ENCODE_name(stname, itname) \
        FC_IMPLEMENT_ASN1_FUNCTIONS_ENCODE_fname(stname, itname, itname)

#define FC_IMPLEMENT_ASN1_FUNCTIONS_fname(stname, itname, fname) \
        FC_IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(stname, itname, fname) \
        FC_IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(stname, itname, fname)

#define FC_IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(stname, itname, fname) \
        stname *fc_d2i_##fname(stname **a, const fc_u8 **in, long len) \
        { \
            return (stname *)FC_ASN1_item_d2i((FC_ASN1_VALUE **)a, in, len, \
                    FC_ASN1_ITEM_rptr(itname));\
        } \
        int fc_i2d_##fname(stname *a, fc_u8 **out) \
        { \
            return FC_ASN1_item_i2d((FC_ASN1_VALUE *)a, out, \
                    FC_ASN1_ITEM_rptr(itname));\
        }

#define FC_IMPLEMENT_ASN1_NDEF_FUNCTION(stname) \
        int fc_i2d_##stname##_NDEF(stname *a, fc_u8 **out) \
        { \
            return FC_ASN1_item_ndef_i2d((FC_ASN1_VALUE *)a, out, \
                    FC_ASN1_ITEM_rptr(stname));\
        }

#define FC_IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(stname) \
        static stname *fc_d2i_##stname(stname **a, \
                                   const fc_u8 **in, long len) \
        { \
            return (stname *)FC_ASN1_item_d2i((FC_ASN1_VALUE **)a, in, len, \
                                               FC_ASN1_ITEM_rptr(stname)); \
        } \
        static int fc_i2d_##stname(stname *a, fc_u8 **out) \
        { \
            return FC_ASN1_item_i2d((FC_ASN1_VALUE *)a, out, \
                                     FC_ASN1_ITEM_rptr(stname)); \
        }


#endif
