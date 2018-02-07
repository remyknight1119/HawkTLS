#ifndef __FC_LOG_H__
#define __FC_LOG_H__

#include <stdio.h>

#define FC_LOG(format, ...) \
    do { \
        fprintf(stdout, "[%s, %d]: "format, __FUNCTION__, \
                __LINE__, ##__VA_ARGS__); \
    } while (0)

#endif
