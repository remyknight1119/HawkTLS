#ifndef __HK_CRYPTO_H__
#define __HK_CRYPTO_H__

#include <sys/types.h>
#include <stdint.h>

#define HK_PEM_DATA_LEN     80

typedef struct _hk_decode_ctx_t {
    int         num;
    int         length;
    uint8_t     data[HK_PEM_DATA_LEN];
    int         line_num;
    int         expect_nl;
} hk_decode_ctx_t;

extern int hk_b64_decode_block(uint8_t *t, const uint8_t *f, int n);
extern int hk_b64_decode(hk_decode_ctx_t *ctx, void *out, int *outl,
            void *in, int inl);
extern int hk_pem_decode(void **out, char *buf, int len);

extern void *hk_crypto_malloc(size_t num, const char *file, int line);
extern void *hk_crypto_calloc(size_t num, const char *file, int line);
extern void hk_crypto_free(void *ptr);

#define hk_malloc(size)     hk_crypto_malloc(size, __FUNCTION__, __LINE__)
#define hk_calloc(size)     hk_crypto_calloc(size, __FUNCTION__, __LINE__)
#define hk_free(ptr)        hk_crypto_free(ptr)

#endif
