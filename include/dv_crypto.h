#ifndef __DV_CRYPTO_H__
#define __DV_CRYPTO_H__

#include <sys/types.h>

#include "dv_types.h"

#define DV_PEM_DATA_LEN     80

typedef struct _dv_decode_ctx_t {
    int         pd_num;
    int         pd_length;
    dv_u8       pd_data[DV_PEM_DATA_LEN];
    int         pd_line_num;
    int         pd_expect_nl;
} dv_decode_ctx_t;

extern int dv_b64_decode_block(dv_u8 *t, const dv_u8 *f, int n);
extern int dv_b64_decode(dv_decode_ctx_t *ctx, void *out, int *outl,
            void *in, int inl);
extern int dv_pem_decode(void **out, char *buf, int len);

extern void *dv_crypto_malloc(size_t num, const char *file, int line);
extern void *dv_crypto_calloc(size_t num, const char *file, int line);
extern void dv_crypto_free(void *ptr);

#define dv_malloc(size)     dv_crypto_malloc(size, __FUNCTION__, __LINE__)
#define dv_calloc(size)     dv_crypto_calloc(size, __FUNCTION__, __LINE__)
#define dv_free(ptr)        dv_crypto_free(ptr)

#endif
