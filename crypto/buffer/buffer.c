#include <stdio.h>
#include <string.h>

#include <falcontls/types.h>
#include <falcontls/crypto.h>
#include <falcontls/buffer.h>

#include "internal/buffer.h"

/*
 * LIMIT_BEFORE_EXPANSION is the maximum n such that (n+3)/3*4 < 2**31. That
 * function is applied in several functions in this file and this limit
 * ensures that the result fits in an int.
 */
#define LIMIT_BEFORE_EXPANSION 0x5ffffffc

FC_BUF_MEM *
FC_BUF_MEM_new_ex(unsigned long flags)
{
    FC_BUF_MEM  *ret = NULL;

    ret = FC_BUF_MEM_new();
    if (ret != NULL) {
        ret->bm_flags = flags;
    }
    return (ret);
}

FC_BUF_MEM *
FC_BUF_MEM_new(void)
{
    FC_BUF_MEM  *ret = NULL;

    ret = FALCONTLS_calloc(sizeof(*ret));
    if (ret == NULL) {
        return (NULL);
    }
    return (ret);
}

void
FC_BUF_MEM_free(FC_BUF_MEM *a)
{
    if (a == NULL) {
        return;
    }

    if (a->bm_data != NULL) {
        FALCONTLS_free(a->bm_data);
    }

    FALCONTLS_free(a);
}

/* 
 * Allocate a block of secure memory; copy over old data if there
 * was any, and then free it. 
 */
static char *
sec_alloc_realloc(FC_BUF_MEM *str, size_t len)
{
    char    *ret = NULL;

    if (str->bm_data == NULL) {
        return NULL;
    }

    ret = FALCONTLS_malloc(len);
    if (ret == NULL) {
        return NULL;
    }
    memcpy(ret, str->bm_data, str->bm_length);
    FALCONTLS_free(str->bm_data);
    str->bm_data = NULL;

    return (ret);
}

static size_t
buf_mem_grow(FC_BUF_MEM *str, size_t len, bool clean)
{
    char *ret;
    size_t n;

    if (str->bm_length >= len) {
        if (clean && str->bm_data != NULL) {
            memset(&str->bm_data[len], 0, str->bm_length - len);
        }
        str->bm_length = len;
        return (len);
    }
    if (str->bm_max >= len) {
        memset(&str->bm_data[str->bm_length], 0, len - str->bm_length);
        str->bm_length = len;
        return (len);
    }
    /* This limit is sufficient to ensure (len+3)/3*4 < 2**31 */
    if (len > LIMIT_BEFORE_EXPANSION) {
        return 0;
    }
    n = (len + 3) / 3 * 4;
    if ((str->bm_flags & FC_BUF_MEM_FLAG_SECURE)) {
        ret = sec_alloc_realloc(str, n);
    } else {
        ret = FALCONTLS_realloc(str->bm_data, n);
    }

    if (ret == NULL) {
        return 0;
    } 

    str->bm_data = ret;
    str->bm_max = n;
    memset(&str->bm_data[str->bm_length], 0, len - str->bm_length);
    str->bm_length = len;
    return (len);
}


size_t
FC_BUF_MEM_grow(FC_BUF_MEM *str, size_t len)
{
    return buf_mem_grow(str, len, 0);
}

size_t
FC_BUF_MEM_grow_clean(FC_BUF_MEM *str, size_t len)
{
    return buf_mem_grow(str, len, 1);
}

#if 0
void FC_BUF_reverse(unsigned char *out, const unsigned char *in, size_t size)
{
    size_t i;
    if (in) {
        out += size - 1;
        for (i = 0; i < size; i++)
            *out-- = *in++;
    } else {
        unsigned char *q;
        char c;
        q = out + size - 1;
        for (i = 0; i < size / 2; i++) {
            c = *q;
            *q-- = *out;
            *out++ = c;
        }
    }
}
#endif

