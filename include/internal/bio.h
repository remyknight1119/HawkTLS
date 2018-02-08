#ifndef __FC_INTERNAL_BIO_H__
#define __FC_INTERNAL_BIO_H__

#include <falcontls/bio.h>

struct fc_bio_method_t {
    int         bm_type;
    const char  *bm_name;
    int         (*bm_write)(FC_BIO *, const char *, int);
    int         (*bm_read)(FC_BIO *, char *, int);
    int         (*bm_puts)(FC_BIO *, const char *);
    int         (*bm_gets)(FC_BIO *, char *, int);
    long        (*bm_ctrl)(FC_BIO *, int, long, void *);
    int         (*bm_create)(FC_BIO *);
    int         (*bm_destroy)(FC_BIO *);
//    long        (*bm_callback_ctrl)(FC_BIO *, int, bio_info_cb *);
};

struct fc_bio_t {
    const FC_BIO_METHOD     *b_method;
    long                    (*b_callback) (struct fc_bio_t *, int,
                                const char *, int, long, long);
    char                    *b_cb_arg;               /* first argument for the callback */
    void                    *b_ptr;
    int                     b_init;
    int                     b_shutdown;
    int                     b_flags;                  /* extra storage */
    int                     b_num;
    int                     b_references;
    fc_u64                  b_num_read;
    fc_u64                  b_num_write;
    //CRYPTO_EX_DATA ex_data;
    //CRYPTO_RWLOCK *lock;
};


#endif
