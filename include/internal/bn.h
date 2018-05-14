#ifndef __INTERNAL_BN_H__
#define __INTERNAL_BN_H__

#include <falcontls/types.h>

struct fc_bn_t {
    FC_BN_ULONG     *d;     /* Pointer to an array of 'BN_BITS2' bit * chunks. */
    int             top;    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int             dmax;   /* Size of the d array. */
    int             neg;    /* one if the number is negative */
    int             flags;
};

#endif
