#include <stdlib.h>

#include "fc_log.h"

void *
fc_crypto_malloc(size_t num, const char *file, int line)
{
    void    *ptr = NULL;

    ptr = malloc(num);
    if (ptr == NULL) {
        FC_LOG("Malloc %d failed!(%s %d)\n", (int)num, file, line);
    }

    return ptr;
}

void *
fc_crypto_calloc(size_t num, const char *file, int line)
{
    void    *ptr = NULL;

    ptr = calloc(1, num);
    if (ptr == NULL) {
        FC_LOG("Malloc %d failed!(%s %d)\n", (int)num, file, line);
    }

    return ptr;
}

void
fc_crypto_free(void *ptr)
{
    free(ptr);
}