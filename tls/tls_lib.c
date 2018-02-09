
#include <falcontls/x509.h>
#include <falcontls/tls.h>
#include <falcontls/crypto.h>

#include "tls_locl.h"


TLS_CTX *
FCTLS_ctx_new(const TLS_METHOD *meth)
{
    TLS_CTX    *ctx = NULL;

    ctx = FALCONTLS_calloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->sc_method = meth;

    return ctx;
}

void 
FCTLS_ctx_free(TLS_CTX *ctx)
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

    if (!s->tls_method->md_tls_new(s)) {
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
FCTLS_accept(TLS *s)
{
    return 0;
}

int
FCTLS_connect(TLS *s)
{
    return 0;
}

int
FCTLS_set_fd(TLS *s, int fd)
{
    return 0;
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


