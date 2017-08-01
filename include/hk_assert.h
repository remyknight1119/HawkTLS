#ifndef __HK_ASSERT_H__
#define __HK_ASSERT_H__

#include <assert.h>
#include "hk_log.h"

#define hk_assert(expr) \
    do {\
        if (!expr) { \
            HK_LOG("%s %d error\n", __FUNCTION__, __LINE__); \
        } \
    } while(0)


#endif
