
#include "hawktls/hk_x509.h"
#include "hawktls/hk_tls.h"
#include "hawktls/hk_crypto.h"


hk_ssl_ctx_t *
hk_ssl_ctx_new(const hk_method_t *meth)
{
    hk_ssl_ctx_t    *ctx = NULL;

    ctx = hk_calloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->sc_method = meth;

    return ctx;
}

void 
hk_ssl_ctx_free(hk_ssl_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    hk_free(ctx);
}

hk_ssl_t *
hk_ssl_new(hk_ssl_ctx_t *ctx)
{
    return NULL;
}

void 
hk_ssl_free(hk_ssl_t *s)
{
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
hk_ssl_accept(hk_ssl_t *s)
{
    return 0;
}

int
hk_ssl_connect(hk_ssl_t *s)
{
    return 0;
}

int
hk_ssl_set_fd(hk_ssl_t *s, int fd)
{
    return 0;
}

void
hk_ssl_set_verify(hk_ssl_t *s, hk_u32 mode,
            int (*callback)(int ok, hk_x509_t *x509))
{
}

int
hk_ssl_read(hk_ssl_t *s, void *buf, hk_u32 len)
{
    return 0;
}

int
hk_ssl_write(hk_ssl_t *s, const void *buf, hk_u32 len)
{
    return 0;
}

int
hk_ssl_shutdown(hk_ssl_t *s)
{
    return 0;
}

