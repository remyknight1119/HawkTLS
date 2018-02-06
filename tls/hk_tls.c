
#include "hawktls/hk_x509.h"
#include "hawktls/hk_tls.h"
#include "hawktls/hk_crypto.h"


TLS_CTX *
hk_tls_ctx_new(const TLS_METHOD *meth)
{
    TLS_CTX    *ctx = NULL;

    ctx = hk_calloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->sc_method = meth;

    return ctx;
}

void 
hk_tls_ctx_free(TLS_CTX *ctx)
{
    if (ctx == NULL) {
        return;
    }

    hk_free(ctx);
}

TLS *
hk_tls_new(TLS_CTX *ctx)
{
    TLS    *s = NULL;

    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->sc_method == NULL) {
        return NULL;
    }

    s = hk_calloc(sizeof(*s));
    if (s == NULL) {
        return NULL;
    }

    s->tls_ctx = ctx;
    s->tls_method = ctx->sc_method;

    return s;
}

void 
hk_tls_free(TLS *s)
{
    if (s == NULL) {
        return;
    }

    hk_free(s);
}

int
hk_library_init(void)
{
    return 0;
}

void
hk_add_all_algorighms(void)
{
}

void
hk_load_error_strings(void)
{
}

int
hk_tls_accept(TLS *s)
{
    return 0;
}

int
hk_tls_connect(TLS *s)
{
    return 0;
}

int
hk_tls_set_fd(TLS *s, int fd)
{
    return 0;
}

void
hk_tls_set_verify(TLS *s, hk_u32 mode,
            int (*callback)(int ok, hk_x509_t *x509))
{
}

int
hk_tls_read(TLS *s, void *buf, hk_u32 len)
{
    return 0;
}

int
hk_tls_write(TLS *s, const void *buf, hk_u32 len)
{
    return 0;
}

int
hk_tls_shutdown(TLS *s)
{
    return 0;
}

