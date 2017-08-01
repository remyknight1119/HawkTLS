#ifndef __HK_LOG_H__
#define __HK_LOG_H__

#include <stdio.h>

#define HK_LOG(priority, format, ...) \
    do { \
        fprintf(stdout, "[%s, %d]: "format, __FUNCTION__, \
                __LINE__, ##__VA_ARGS__); \
    } while (0)

#endif
