
#include <falcontls/types.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>

#include "internal/bio.h"


FC_BIO *FC_BIO_new(const FC_BIO_METHOD *method)
{
    FC_BIO *bio = NULL;
    
    bio = FALCONTLS_calloc(sizeof(*bio));
    if (bio == NULL) {
        return NULL;
    }

    bio->b_method = method;
    bio->b_shutdown = 1;
    bio->b_references = 1;

#if 0
    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_FC_BIO, bio, &bio->ex_data))
        goto err;

    bio->lock = CRYPTO_THREAD_lock_new();
    if (bio->lock == NULL) {
        FC_BIOerr(FC_BIO_F_FC_BIO_NEW, ERR_R_MALLOC_FAILURE);
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_FC_BIO, bio, &bio->ex_data);
        goto err;
    }
#endif

    if (method->bm_create != NULL && !method->bm_create(bio)) {
#if 0
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_FC_BIO, bio, &bio->ex_data);
        CRYPTO_THREAD_lock_free(bio->lock);
#endif
        goto err;
    }

    return bio;

err:
    FALCONTLS_free(bio);
    return NULL;
}

int FC_BIO_free(FC_BIO *a)
{
//    int i;

    if (a == NULL) {
        return 0;
    }

#if 0
    if (CRYPTO_atomic_add(&a->references, -1, &i, a->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("FC_BIO", a);
    if (i > 0)
        return 1;
    REF_ASSERT_ISNT(i < 0);
    if ((a->callback != NULL) &&
        ((i = (int)a->callback(a, FC_BIO_CB_FREE, NULL, 0, 0L, 1L)) <= 0))
        return i;
#endif

    if ((a->b_method != NULL) && (a->b_method->bm_destroy != NULL)) {
        a->b_method->bm_destroy(a);
    }

#if 0
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_FC_BIO, a, &a->ex_data);

    CRYPTO_THREAD_lock_free(a->lock);
#endif

    FALCONTLS_free(a);

    return 1;
}

void FC_BIO_set_data(FC_BIO *a, void *ptr)
{
    a->b_ptr = ptr;
}

void *FC_BIO_get_data(FC_BIO *a)
{
    return a->b_ptr;
}

void FC_BIO_set_init(FC_BIO *a, int init)
{
    a->b_init = init;
}

int FC_BIO_get_init(FC_BIO *a)
{
    return a->b_init;
}

void FC_BIO_set_shutdown(FC_BIO *a, int shut)
{
    a->b_shutdown = shut;
}

int FC_BIO_get_shutdown(FC_BIO *a)
{
    return a->b_shutdown;
}

void FC_BIO_vfree(FC_BIO *a)
{
    FC_BIO_free(a);
}

int FC_BIO_read(FC_BIO *b, void *out, int outl)
{
    int i;
    //long (*cb) (FC_BIO *, int, const char *, int, long, long);

    if ((b == NULL) || (b->b_method == NULL) || 
            (b->b_method->bm_read == NULL)) {
        return -2;
    }

#if 0
    cb = b->callback;
    if ((cb != NULL) &&
        ((i = (int)cb(b, BIO_CB_READ, out, outl, 0L, 1L)) <= 0))
        return (i);

    if (!b->init) {
        BIOerr(BIO_F_BIO_READ, BIO_R_UNINITIALIZED);
        return (-2);
    }
#endif

    i = b->b_method->bm_read(b, out, outl);
    if (i > 0) {
        b->b_num_read += (fc_u64)i;
    }

#if 0
    if (cb != NULL)
        i = (int)cb(b, BIO_CB_READ | BIO_CB_RETURN, out, outl, 0L, (long)i);
#endif

    return (i);
}

int FC_BIO_write(FC_BIO *b, const void *in, int inl)
{
    int i;
    //long (*cb) (BIO *, int, const char *, int, long, long);

    if (b == NULL) {
        return (0);
    }

#if 0
    cb = b->callback;
#endif
    if ((b->b_method == NULL) || (b->b_method->bm_write == NULL)) {
        return (-2);
    }

#if 0
    if ((cb != NULL) &&
        ((i = (int)cb(b, BIO_CB_WRITE, in, inl, 0L, 1L)) <= 0))
        return (i);

    if (!b->init) {
        BIOerr(BIO_F_BIO_WRITE, BIO_R_UNINITIALIZED);
        return (-2);
    }
#endif

    i = b->b_method->bm_write(b, in, inl);
    if (i > 0) {
        b->b_num_write += (fc_u64)i;
    }

#if 0
    if (cb != NULL)
        i = (int)cb(b, BIO_CB_WRITE | BIO_CB_RETURN, in, inl, 0L, (long)i);
#endif

    return (i);
}

int FC_BIO_puts(FC_BIO *b, const char *in)
{
    int i;
//    long (*cb) (BIO *, int, const char *, int, long, long);

    if ((b == NULL) || (b->b_method == NULL) || 
            (b->b_method->bm_puts == NULL)) {
        return (-2);
    }

#if 0
    cb = b->callback;

    if ((cb != NULL) && ((i = (int)cb(b, BIO_CB_PUTS, in, 0, 0L, 1L)) <= 0))
        return (i);

    if (!b->init) {
        return (-2);
    }
#endif

    i = b->b_method->bm_puts(b, in);
    if (i > 0) {
        b->b_num_write += (fc_u64)i;
    }

#if 0
    if (cb != NULL)
        i = (int)cb(b, BIO_CB_PUTS | BIO_CB_RETURN, in, 0, 0L, (long)i);
#endif

    return (i);
}

int FC_BIO_gets(FC_BIO *b, char *in, int inl)
{
    int i;
//    long (*cb) (BIO *, int, const char *, int, long, long);

    if ((b == NULL) || (b->b_method == NULL) || 
            (b->b_method->bm_gets == NULL)) {
        return (-2);
    }

#if 0
    cb = b->callback;

    if ((cb != NULL) && ((i = (int)cb(b, BIO_CB_GETS, in, inl, 0L, 1L)) <= 0))
        return (i);

    if (!b->init) {
        BIOerr(BIO_F_BIO_GETS, BIO_R_UNINITIALIZED);
        return (-2);
    }
#endif

    i = b->b_method->bm_gets(b, in, inl);
#if 0
    if (cb != NULL)
        i = (int)cb(b, BIO_CB_GETS | BIO_CB_RETURN, in, inl, 0L, (long)i);
#endif
    return (i);
}


