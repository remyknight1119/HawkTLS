#ifndef __FC_INTERNAL_BIO_H__
#define __FC_INTERNAL_BIO_H__

#include <falcontls/bio.h>

#include <openssl/bio.h>

struct fc_bio_method_t {
#ifdef FC_OPENSSL
    BIO_METHOD  *m;
#endif
    int         bm_type;
    const char  *bm_name;
    int         (*bm_write)(FC_BIO *, const char *, int);
    int         (*bm_read)(FC_BIO *, char *, int);
    int         (*bm_puts)(FC_BIO *, const char *);
    int         (*bm_gets)(FC_BIO *, char *, int);
    long        (*bm_ctrl)(FC_BIO *, int, long, void *);
    int         (*bm_create)(FC_BIO *);
    int         (*bm_destroy)(FC_BIO *);
};

struct fc_bio_t {
#ifdef FC_OPENSSL
    BIO                     *b;
#endif
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
