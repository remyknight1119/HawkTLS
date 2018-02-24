#ifndef __FC_LOG_H__
#define __FC_LOG_H__

#include <stdio.h>

#define FC_LOG(format, ...) \
    do { \
        fprintf(stdout, "[%s, %d]: "format, __FUNCTION__, \
                __LINE__, ##__VA_ARGS__); \
    } while (0)

static inline void print_data(unsigned char *data, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}


#endif
