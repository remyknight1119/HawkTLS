#ifndef __FC_PRINT_H__
#define __FC_PRINT_H__

#include <stdio.h>

static inline void
fc_print(unsigned char *data, int len)
{
    int     i = 0;

    for (i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\nlen = %d\n", len);
}

#endif
