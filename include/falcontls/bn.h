#ifndef __FC_BN_H__
#define __FC_BN_H__

#include <stdint.h>
#include <limits.h>

#include <falcontls/types.h>

#define FC_BN_BYTES	    8
#define FC_BN_BITS2	    64
#define FC_BN_BITS4	    32
#define FC_BN_MASK2	    (0xffffffffffffffffL)

#define FC_BN_abs_is_word(a, w) ((((a)->top == 1) && \
                ((a)->d[0] == (BN_ULONG)(w))) || \
				(((w) == 0) && ((a)->top == 0)))
#define FC_BN_is_zero(a)       ((a)->top == 0)
#define FC_BN_is_one(a)        (FC_BN_abs_is_word((a), 1) && !(a)->neg)
#define FC_BN_is_word(a, w)    (FC_BN_abs_is_word((a), (w)) && (!(w) || !(a)->neg))
#define FC_BN_is_odd(a)	    (((a)->top > 0) && ((a)->d[0] & 1))

#define FC_BN_num_bytes(a)	((FC_BN_num_bits(a) + 7)/8)
#define FC_BN_zero(a)	(FC_BN_set_word((a),0))
#define FC_BN_get_flags(b, n)   ((b)->flags & (n))

extern int FC_BN_num_bits(const FC_BIGNUM *a);
extern int FC_BN_ucmp(const FC_BIGNUM *a, const FC_BIGNUM *b);
extern int FC_BN_set_word(FC_BIGNUM *a, FC_BN_ULONG w);
extern int FC_BN_bn2bin(const FC_BIGNUM *a, unsigned char *to);
extern void FC_BN_init(FC_BIGNUM *a);
extern void FC_BN_clear_free(FC_BIGNUM *a);
extern void FC_BN_free(FC_BIGNUM *bn);
extern FC_BIGNUM *FC_BN_bin2bn(const uint8_t *s, int len, FC_BIGNUM *ret);
extern FC_BN_ULONG FC_BN_add_words(FC_BN_ULONG *r, const FC_BN_ULONG *a, 
        const FC_BN_ULONG *b, int n);
//extern FC_BIGNUM *FC_BN_CTX_get(FC_BN_CTX *ctx);
//extern FC_BN_CTX *FC_BN_CTX_new(void);
//extern void FC_BN_CTX_free(FC_BN_CTX *ctx);
//extern void FC_BN_CTX_end(FC_BN_CTX *ctx);


extern int FC_BN_uadd(FC_BIGNUM *r, const FC_BIGNUM *a, const FC_BIGNUM *b);
extern int FC_BN_mul(FC_BIGNUM *r, const FC_BIGNUM *a, const FC_BIGNUM *b);

#endif
