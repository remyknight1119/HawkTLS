#include <stdlib.h>

#include "hk_log.h"

void *
hk_crypto_malloc(size_t num, const char *file, int line)
{
    void    *ptr = NULL;

    ptr = malloc(num);
    if (ptr == NULL) {
        HK_LOG("Malloc %d failed!(%s %d)\n", (int)num, file, line);
    }

    return ptr;
}

void *
hk_crypto_calloc(size_t num, const char *file, int line)
{
    void    *ptr = NULL;

    ptr = calloc(1, num);
    if (ptr == NULL) {
        HK_LOG("Malloc %d failed!(%s %d)\n", (int)num, file, line);
    }

    return ptr;
}

void
hk_crypto_free(void *ptr)
{
    free(ptr);
}
