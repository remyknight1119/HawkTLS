#ifndef __HK_BN_H__
#define __HK_BN_H__

#include <stdint.h>

typedef unsigned long BN_ULONG;

typedef struct _hk_bn_t {
    BN_ULONG    *d;     /* Pointer to an array of 'BN_BITS2' bit * chunks. */
    int         top;    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int         dmax;   /* Size of the d array. */
    int         neg;    /* one if the number is negative */
    int         flags;
} hk_bn_t;

typedef hk_bn_t BIGNUM;

extern int hk_bn_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

#endif
