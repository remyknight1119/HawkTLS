#ifndef __FC_CRYPTO_H__
#define __FC_CRYPTO_H__

#include <sys/types.h>
#include <stdint.h>

#include <falcontls/safestack.h>
#include <falcontls/types.h>

#define FC_CRYPTO_add(a,b,c)       ((*(a))+=(b))
#define FC_PEM_DATA_LEN     80

typedef struct FC_DECODE_CTX {
    int         num;
    int         length;
    uint8_t     data[FC_PEM_DATA_LEN];
    int         line_num;
    int         expect_nl;
} FC_DECODE_CTX;

#if 0
struct crypto_ex_data_st {
    STACK_OF(void) *sk;   
};
//DECLARE_STACK_OF(void)
#endif

extern int fc_b64_decode_block(uint8_t *t, const uint8_t *f, int n);
extern int fc_b64_decode(FC_DECODE_CTX *ctx, void *out, int *outl,
            void *in, int inl);
extern int fc_pem_decode(void **out, char *buf, int len);

extern void *FC_CRYPTO_malloc(size_t num, const char *file, int line);
extern void *FC_CRYPTO_calloc(size_t num, const char *file, int line);
extern void *FC_CRYPTO_realloc(void *str, size_t num, 
            const char *file, int line);
extern void FC_CRYPTO_free(void *ptr);

#define FALCONTLS_malloc(size)          \
            FC_CRYPTO_malloc(size, __FUNCTION__, __LINE__)
#define FALCONTLS_calloc(size)          \
            FC_CRYPTO_calloc(size, __FUNCTION__, __LINE__)
#define FALCONTLS_realloc(ptr, size)    \
            FC_CRYPTO_realloc(ptr, size, __FUNCTION__, __LINE__)
#define FALCONTLS_free(ptr)             FC_CRYPTO_free(ptr)

#define FC_CRYPTO_LOCK_RSA          9

#define CRYPTO_EX_INDEX_RSA         6

//int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
//void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);

#endif
