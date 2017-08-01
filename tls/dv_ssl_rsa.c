
#include "dv_ssl.h"
#include "dv_types.h"
#include "dv_errno.h"
#include "dv_crypto.h"
#include "dv_debug.h"

int 
dv_ssl_ctx_use_certificate_file(dv_ssl_ctx_t *ctx,
        const char *file, dv_u32 type)
{
    void    *pem = NULL;
    int     len = 0;

    if (ctx->sc_ca != NULL) {
        DV_DEBUG("CA already load!\n");
        return DV_ERROR;
    } 

    len = ctx->sc_method->md_bio_read_file(file, &pem);
    if (len <= 0) {
        DV_DEBUG("Read failed!\n");
        return DV_ERROR;
    }

    len = dv_pem_decode(&ctx->sc_ca, pem, len);
    dv_free(pem);
    if (len <= 0) {
        DV_DEBUG("Decode failed!len = %d\n", len);
        return DV_ERROR;
    }

    ctx->sc_ca_len = len;

    return DV_OK;
}

int
dv_ssl_ctx_use_private_key_file(dv_ssl_ctx_t *ctx,
        const char *file, dv_u32 type)
{
    return DV_OK;
}

int
dv_ssl_ctx_check_private_key(const dv_ssl_ctx_t *ctx)
{
    return DV_OK;
}
