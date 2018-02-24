
#include <falcontls/tls.h>
#include <falcontls/crypto.h>
#include <falcontls/x509.h>
#include <falcontls/bio.h>
#include <fc_log.h>

#include "tls_locl.h"


TLS_CTX *
FCTLS_CTX_new(const TLS_METHOD *meth)
{
    TLS_CTX    *ctx = NULL;

    ctx = FALCONTLS_calloc(sizeof(*ctx));
    if (ctx == NULL) {
        FC_LOG("Alloc ctx failed!\n");
        return NULL;
    }

    ctx->sc_method = meth;
    ctx->sc_max_send_fragment = FC_TLS_RT_MAX_PLAIN_LENGTH;
    ctx->sc_split_send_fragment = FC_TLS_RT_MAX_PLAIN_LENGTH;

    return ctx;
}

void 
FCTLS_CTX_free(TLS_CTX *ctx)
{
    if (ctx == NULL) {
        return;
    }

    FALCONTLS_free(ctx);
}

int
FCTLS_clear(TLS *s)
{
    if (s->tls_method == NULL) {
        return 0;
    }

    s->tls_method->md_tls_clear(s);

    return 1;
}

TLS *
FCTLS_new(TLS_CTX *ctx)
{
    TLS    *s = NULL;

    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->sc_method == NULL) {
        return NULL;
    }

    s = FALCONTLS_calloc(sizeof(*s));
    if (s == NULL) {
        return NULL;
    }

    s->tls_ctx = ctx;
    s->tls_method = ctx->sc_method;
    s->tls_max_send_fragment = ctx->sc_max_send_fragment;
    s->tls_split_send_fragment = ctx->sc_split_send_fragment;
    s->tls_max_pipelines = ctx->sc_max_pipelines;

    if (!s->tls_method->md_tls_new(s)) {
        FC_LOG("TLS new failed\n");
        goto err;
    }

    if (!FCTLS_clear(s)) {
        goto err;
    }

    return s;
err:
    FALCONTLS_free(s);
    return NULL;
}

void 
FCTLS_free(TLS *s)
{
    if (s == NULL) {
        return;
    }

    if (s->tls_method != NULL) {
        s->tls_method->md_tls_free(s);
    }

    FALCONTLS_free(s);
}

int
FCTLS_do_handshake(TLS *s)
{
    int ret = 1;

    if (s->tls_handshake_func == NULL) {
        return -1;
    }

    s->tls_method->md_tls_renegotiate_check(s);

    if (TLS_init(s)) {
        ret = s->tls_handshake_func(s);
    }

    return ret;
}

TLS_RWSTATE
TLS_want(const TLS *s)
{
    return (s->tls_rwstate);
}

void 
FCTLS_set_accept_state(TLS *s)
{
    s->tls_server = 1;
    s->tls_shutdown = 0;
    //ossl_statem_clear(s);
    s->tls_handshake_func = s->tls_method->md_tls_accept;
    //clear_ciphers(s);
}

void
FCTLS_set_connect_state(TLS *s)
{
    s->tls_server = 0;
    s->tls_shutdown = 0;
    //ossl_statem_clear(s);
    s->tls_handshake_func = s->tls_method->md_tls_connect;
    //clear_ciphers(s);
}

int
tls_undefined_function(TLS *s)
{
    return (0);
}

int
tls_undefined_void_function(void)
{
    return (0);
}

int
tls_undefined_const_function(const TLS *s)
{
    return (0);
}

int
FCTLS_accept(TLS *s)
{
    if (s->tls_handshake_func == NULL) {
        FCTLS_set_accept_state(s);
    }

    return FCTLS_do_handshake(s);
}

int
FCTLS_connect(TLS *s)
{
    if (s->tls_handshake_func == NULL) {
        FCTLS_set_connect_state(s);
    }

    return FCTLS_do_handshake(s);
}

FC_BIO *
FCTLS_get_rbio(const TLS *s)
{
    return s->tls_rbio;
}

FC_BIO *
FCTLS_get_wbio(const TLS *s)
{
    return s->tls_wbio;
}

void
FCTLS_set0_rbio(TLS *s, FC_BIO *rbio)
{
    FC_BIO_free(s->tls_rbio);
    s->tls_rbio = rbio;
}

void
FCTLS_set0_wbio(TLS *s, FC_BIO *wbio)
{
    FC_BIO_free(s->tls_wbio);
    s->tls_wbio = wbio;
}

void 
FCTLS_set_bio(TLS *s, FC_BIO *rbio, FC_BIO *wbio)
{
    if (rbio == FCTLS_get_rbio(s) && wbio == FCTLS_get_wbio(s)) {
        return;
    }

#if 0
    if (rbio != NULL && rbio == wbio)
        BIO_up_ref(rbio);
#endif

    if (rbio == FCTLS_get_rbio(s)) {
        FCTLS_set0_wbio(s, wbio);
        return;
    }

    if (wbio == FCTLS_get_wbio(s)) {
        FCTLS_set0_rbio(s, rbio);
        return;
    }

    FCTLS_set0_rbio(s, rbio);
    FCTLS_set0_wbio(s, wbio);
}

int
FCTLS_set_fd(TLS *s, int fd)
{
    int     ret = 0;
    FC_BIO  *bio = NULL;

    bio = FC_BIO_new(FC_BIO_s_socket());
    if (bio == NULL) {
        goto err;
    }

    FC_BIO_set_fd(bio, fd, FC_BIO_NOCLOSE);
    FCTLS_set_bio(s, bio, bio);
    ret = 1;
 err:
    return (ret);
}

int
FCTLS_CTX_check_private_key(const TLS_CTX *ctx)
{
    if ((ctx == NULL) || (ctx->sc_cert->ct_key->cp_x509 == NULL)) {
        return (0);
    }

    if (ctx->sc_cert->ct_key->cp_privatekey == NULL) {
        return (0);
    }

    return (FC_X509_check_private_key(ctx->sc_cert->ct_key->cp_x509,
                ctx->sc_cert->ct_key->cp_privatekey));
}

int
FCTLS_check_private_key(const TLS *s)
{
    if (s == NULL) {
        return (0);
    }

    if (s->tls_cert->ct_key->cp_x509 == NULL) {
        return (0);
    }

    if (s->tls_cert->ct_key->cp_privatekey == NULL) {
        return (0);
    }

    return (FC_X509_check_private_key(s->tls_cert->ct_key->cp_x509,
                s->tls_cert->ct_key->cp_privatekey));
}


void
FCTLS_set_verify(TLS *s, fc_u32 mode,
            int (*callback)(int ok, FC_X509 *x509))
{
}

int
FCTLS_read(TLS *s, void *buf, fc_u32 len)
{
    return 0;
}

int
FCTLS_write(TLS *s, const void *buf, fc_u32 len)
{
    return 0;
}

int
FCTLS_shutdown(TLS *s)
{
    return 0;
}

int
FALCONTLS_init(void)
{
    return 0;
}

void
FalconTLS_add_all_algorighms(void)
{
}


