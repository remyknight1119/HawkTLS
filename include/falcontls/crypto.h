#ifndef __FC_CRYPTO_H__
#define __FC_CRYPTO_H__

#include <sys/types.h>
#include <stdint.h>

#include <falcontls/safestack.h>
#include <falcontls/types.h>

#define FC_CRYPTO_add(a,b,c)       ((*(a))+=(b))
#define FC_PEM_DATA_LEN     80

typedef struct _fc_decode_ctx_t {
    int         num;
    int         length;
    uint8_t     data[FC_PEM_DATA_LEN];
    int         line_num;
    int         expect_nl;
} fc_decode_ctx_t;

#if 0
struct crypto_ex_data_st {
    STACK_OF(void) *sk;   
};
//DECLARE_STACK_OF(void)
#endif

extern int fc_b64_decode_block(uint8_t *t, const uint8_t *f, int n);
extern int fc_b64_decode(fc_decode_ctx_t *ctx, void *out, int *outl,
            void *in, int inl);
extern int fc_pem_decode(void **out, char *buf, int len);

extern void *fc_crypto_malloc(size_t num, const char *file, int line);
extern void *fc_crypto_calloc(size_t num, const char *file, int line);
extern void fc_crypto_free(void *ptr);

#define fc_malloc(size)     fc_crypto_malloc(size, __FUNCTION__, __LINE__)
#define fc_calloc(size)     fc_crypto_calloc(size, __FUNCTION__, __LINE__)
#define fc_free(ptr)        fc_crypto_free(ptr)

#define FC_CRYPTO_LOCK_RSA          9

#define CRYPTO_EX_INDEX_RSA         6

int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);

#endif
