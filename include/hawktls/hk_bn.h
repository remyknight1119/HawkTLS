#ifndef __HK_BN_H__
#define __HK_BN_H__

#include <stdint.h>
#include <limits.h>

typedef unsigned long BN_ULONG;

#define HK_BN_BYTES	    8
#define HK_BN_BITS2	    64
#define HK_BN_BITS4	    32

#define hk_bn_abs_is_word(a, w) ((((a)->top == 1) && \
                ((a)->d[0] == (BN_ULONG)(w))) || \
				(((w) == 0) && ((a)->top == 0)))
#define hk_bn_is_zero(a)       ((a)->top == 0)
#define hk_bn_is_one(a)        (hk_bn_abs_is_word((a), 1) && !(a)->neg)
#define hk_bn_is_word(a,w)     (hk_bn_abs_is_word((a),(w)) && (!(w) || !(a)->neg))
#define hk_bn_is_odd(a)	    (((a)->top > 0) && ((a)->d[0] & 1))

#define hk_bn_num_bytes(a)	((hk_bn_num_bits(a) + 7)/8)
#define hk_bn_zero(a)	(hk_bn_set_word((a),0))

typedef struct _hk_bn_t {
    BN_ULONG    *d;     /* Pointer to an array of 'BN_BITS2' bit * chunks. */
    int         top;    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int         dmax;   /* Size of the d array. */
    int         neg;    /* one if the number is negative */
    int         flags;
} hk_bn_t;

typedef hk_bn_t BIGNUM;

extern int hk_bn_num_bits(const BIGNUM *a);
extern int hk_bn_ucmp(const BIGNUM *a, const BIGNUM *b);
extern int hk_bn_set_word(BIGNUM *a, BN_ULONG w);
extern int hk_bn_bn2bin(const BIGNUM *a, unsigned char *to);
extern void hk_bn_init(BIGNUM *a);
extern void hk_bn_clear_free(BIGNUM *a);
extern BIGNUM *hk_bn_bin2bn(const uint8_t *s, int len, BIGNUM *ret);
//extern BIGNUM *hk_bn_CTX_get(HK_BN_CTX *ctx);
//extern HK_BN_CTX *hk_bn_CTX_new(void);
//extern void hk_bn_CTX_free(HK_BN_CTX *ctx);
//extern void hk_bn_CTX_end(HK_BN_CTX *ctx);


extern int hk_bn_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

#endif
