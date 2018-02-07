
#include "falcontls/x509.h"
#include "falcontls/tls.h"
#include "falcontls/crypto.h"


TLS_CTX *
fc_tls_ctx_new(const TLS_METHOD *meth)
{
    TLS_CTX    *ctx = NULL;

    ctx = fc_calloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->sc_method = meth;

    return ctx;
}

void 
fc_tls_ctx_free(TLS_CTX *ctx)
{
    if (ctx == NULL) {
        return;
    }

    fc_free(ctx);
}

TLS *
fc_tls_new(TLS_CTX *ctx)
{
    TLS    *s = NULL;

    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->sc_method == NULL) {
        return NULL;
    }

    s = fc_calloc(sizeof(*s));
    if (s == NULL) {
        return NULL;
    }

    s->tls_ctx = ctx;
    s->tls_method = ctx->sc_method;

    return s;
}

void 
fc_tls_free(TLS *s)
{
    if (s == NULL) {
        return;
    }

    fc_free(s);
}

int
fc_library_init(void)
{
    return 0;
}

void
fc_add_all_algorighms(void)
{
}

void
fc_load_error_strings(void)
{
}

int
fc_tls_accept(TLS *s)
{
    return 0;
}

int
fc_tls_connect(TLS *s)
{
    return 0;
}

int
fc_tls_set_fd(TLS *s, int fd)
{
    return 0;
}

void
fc_tls_set_verify(TLS *s, fc_u32 mode,
            int (*callback)(int ok, FC_X509 *x509))
{
}

int
fc_tls_read(TLS *s, void *buf, fc_u32 len)
{
    return 0;
}

int
fc_tls_write(TLS *s, const void *buf, fc_u32 len)
{
    return 0;
}

int
fc_tls_shutdown(TLS *s)
{
    return 0;
}

