#ifndef __FC_ASN1T_H__
#define __FC_ASN1T_H__

#include <falcontls/asn1.h>

#ifndef offsetof
#define offsetof(type, member) ((int) & ((type*)0) -> member)
#endif

/* Macros for start and end of ASN1_ITEM definition */

#define FC_ASN1_ITEM_start(itname) \
        const FC_ASN1_ITEM itname##_it = {

#define static_FC_ASN1_ITEM_start(itname) \
        static const FC_ASN1_ITEM itname##_it = {

#define FC_ASN1_ITEM_end(itname)                 \
                };


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
        stname *d2i_##fname(stname **a, const fc_u8 **in, long len) \
        { \
            return (stname *)FC_ASN1_item_d2i((FC_ASN1_VALUE **)a, in, len, \
                    FC_ASN1_ITEM_rptr(itname));\
        } \
        int i2d_##fname(stname *a, fc_u8 **out) \
        { \
            return FC_ASN1_item_i2d((FC_ASN1_VALUE *)a, out, \
                    FC_ASN1_ITEM_rptr(itname));\
        }

#define FC_IMPLEMENT_ASN1_NDEF_FUNCTION(stname) \
        int i2d_##stname##_NDEF(stname *a, fc_u8 **out) \
        { \
            return FC_ASN1_item_ndef_i2d((FC_ASN1_VALUE *)a, out, \
                    FC_ASN1_ITEM_rptr(stname));\
        }

#define FC_IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(stname) \
        static stname *d2i_##stname(stname **a, \
                                   const fc_u8 **in, long len) \
        { \
            return (stname *)FC_ASN1_item_d2i((FC_ASN1_VALUE **)a, in, len, \
                                               FC_ASN1_ITEM_rptr(stname)); \
        } \
        static int i2d_##stname(stname *a, fc_u8 **out) \
        { \
            return FC_ASN1_item_i2d((FC_ASN1_VALUE *)a, out, \
                                     FC_ASN1_ITEM_rptr(stname)); \
        }

#define FC_IMPLEMENT_ASN1_ALLOC_FUNCTIONS_pfname(pre, stname, itname, fname) \
        pre stname *fname##_new(void) \
        { \
            return (stname *)FC_ASN1_item_new(FC_ASN1_ITEM_rptr(itname)); \
        } \
        pre void fname##_free(stname *a) \
        { \
            FC_ASN1_item_free((FC_ASN1_VALUE *)a, FC_ASN1_ITEM_rptr(itname)); \
        }

#define FC_IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(stname, itname, fname) \
        stname *fname##_new(void) \
        { \
            return (stname *)FC_ASN1_item_new(FC_ASN1_ITEM_rptr(itname)); \
        } \
        void fname##_free(stname *a) \
        { \
            FC_ASN1_item_free((FC_ASN1_VALUE *)a, FC_ASN1_ITEM_rptr(itname)); \
        }

/* This is a ASN1 type which just embeds a template */

/*-
 * This pair helps declare a SEQUENCE. We can do:
 *
 *      FC_ASN1_SEQUENCE(stname) = {
 *              ... SEQUENCE components ...
 *      } FC_ASN1_SEQUENCE_END(stname)
 *
 *      This will produce an ASN1_ITEM called stname_it
 *      for a structure called stname.
 *
 *      If you want the same structure but a different
 *      name then use:
 *
 *      FC_ASN1_SEQUENCE(itname) = {
 *              ... SEQUENCE components ...
 *      } FC_ASN1_SEQUENCE_END_name(stname, itname)
 *
 *      This will create an item called itname_it using
 *      a structure called stname.
 */

#define FC_ASN1_SEQUENCE(tname) \
        static const FC_ASN1_TEMPLATE tname##_seq_tt[]


#define FC_ASN1_SEQUENCE_ref(tname, cb) \
        static const FC_ASN1_AUX tname##_aux = { \
            cb, \
            NULL, \
            FC_ASN1_AFLG_REFCOUNT, \
            offsetof(tname, references), \
            offsetof(tname, lock), \
            0 \
        }; \
        FC_ASN1_SEQUENCE(tname)

/*
 * This is the FC_ASN1_AUX structure: it handles various miscellaneous
 * requirements. For example the use of reference counts and an informational
 * callback. The "informational callback" is called at various points during
 * the ASN1 encoding and decoding. It can be used to provide minor
 * customisation of the structures used. This is most useful where the
 * supplied routines *almost* do the right thing but need some extra help at
 * a few points. If the callback returns zero then it is assumed a fatal
 * error has occurred and the main operation should be abandoned. If major
 * changes in the default behaviour are required then an external type is
 * more appropriate.
 */

typedef int FC_ASN1_aux_cb(int operation, FC_ASN1_VALUE **in,
                        const FC_ASN1_ITEM *it, void *exarg);

typedef struct FC_ASN1_AUX_t {
    FC_ASN1_aux_cb  *asn1_cb;
    void            *app_data;
    int             flags;
    int             ref_offset;  /* Offset of reference value */
    int             ref_lock;    /* Lock type to use */
    int             enc_offset;  /* Offset of FC_ASN1_ENCODING structure */
} FC_ASN1_AUX;

/* Use a reference count */
#define FC_ASN1_AFLG_REFCOUNT       1
/* Save the encoding of structure (useful for signatures) */
#define FC_ASN1_AFLG_ENCODING       2
/* The Sequence length is invalid */
#define FC_ASN1_AFLG_BROKEN         4



#endif
