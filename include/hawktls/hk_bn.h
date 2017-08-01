#ifndef __HK_BN_H__
#define __HK_BN_H__

#include <stdint.h>

typedef struct _hk_bn_t {
    uint8_t       *bn_num;
    uint32_t      bn_len;
} hk_bn_t;

#endif
