#ifndef __FC_ASN1T_H__
#define __FC_ASN1T_H__

#include <falcontls/asn1.h>

#ifndef offsetof
#define offsetof(type, member) ((int) & ((type*)0) -> member)
#endif

#define FC_ASN1_ITYPE_PRIMITIVE         0x0
#define FC_ASN1_ITYPE_SEQUENCE          0x1
#define FC_ASN1_ITYPE_CHOICE            0x2
#define FC_ASN1_ITYPE_EXTERN            0x4
#define FC_ASN1_ITYPE_MSTRING           0x5
#define FC_ASN1_ITYPE_NDEF_SEQUENCE     0x6


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
            .asn1_cb = cb, \
            .app_data = NULL, \
            .flags = FC_ASN1_AFLG_REFCOUNT, \
            .ref_offset = offsetof(tname, references), \
            .ref_lock = offsetof(tname, lock), \
            .enc_offset = 0 \
        }; \
        FC_ASN1_SEQUENCE(tname)

#define FC_ASN1_SEQUENCE_END_ref(stname, tname) \
        ;\
        FC_ASN1_ITEM_start(tname) \
                FC_ASN1_ITYPE_SEQUENCE,\
                FC_V_ASN1_SEQUENCE,\
                tname##_seq_tt,\
                sizeof(tname##_seq_tt) / sizeof(FC_ASN1_TEMPLATE),\
                &tname##_aux,\
                sizeof(stname),\
                #stname \
        FC_ASN1_ITEM_end(tname)

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

/*
 * This is the ASN1 template structure that defines a wrapper round the
 * actual type. It determines the actual position of the field in the value
 * structure, various flags such as OPTIONAL and the field name.
 */

struct FC_SN1_TEMPLATE_t {
    unsigned long flags;        /* Various flags */
    long tag;                   /* tag, not used if no tagging */
    unsigned long offset;       /* Offset of this field in structure */
    const char *field_name;     /* Field name */
    FC_ASN1_ITEM_EXP *item;        /* Relevant ASN1_ITEM or ASN1_ADB */
};

/* This is the actual ASN1 item itself */

struct FC_ASN1_ITEM_t {
    char itype;                 /* The item type, primitive, SEQUENCE, CHOICE
                                 * or extern */
    long utype;                 /* underlying type */
    const FC_ASN1_TEMPLATE *templates; /* If SEQUENCE or CHOICE this contains
                                     * the contents */
    long tcount;                /* Number of templates if SEQUENCE or CHOICE */
    const void *funcs;          /* functions that handle this type */
    long size;                  /* Structure size (usually) */
    const char *sname;          /* Structure name */
};

/*
 * This is the ASN1 template structure that defines a wrapper round the
 * actual type. It determines the actual position of the field in the value
 * structure, various flags such as OPTIONAL and the field name.
 */

struct FC_ASN1_TEMPLATE_t {
    unsigned long flags;        /* Various flags */
    long tag;                   /* tag, not used if no tagging */
    unsigned long offset;       /* Offset of this field in structure */
    const char *field_name;     /* Field name */
    FC_ASN1_ITEM_EXP *item;        /* Relevant ASN1_ITEM or ASN1_ADB */
};


/* Use a reference count */
#define FC_ASN1_AFLG_REFCOUNT       1
/* Save the encoding of structure (useful for signatures) */
#define FC_ASN1_AFLG_ENCODING       2
/* The Sequence length is invalid */
#define FC_ASN1_AFLG_BROKEN         4

#define FC_ASN1_TFLG_EMBED         (0x1 << 12)

#define FC_ASN1_EX_TYPE(flags, tag, stname, field, type) { \
        (flags), (tag), offsetof(stname, field),\
        #field, FC_ASN1_ITEM_ref(type) }

#define FC_ASN1_EMBED(stname, field, type) \
            FC_ASN1_EX_TYPE(FC_ASN1_TFLG_EMBED,0, stname, field, type) 


#endif
