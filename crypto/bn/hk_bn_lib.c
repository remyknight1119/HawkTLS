#include <string.h>

#include "hawktls/hk_bn.h"
#include "hk_bn_lcl.h"
#include "hk_crypto.h"

void
hk_bn_init(BIGNUM *a)
{
	memset(a, 0, sizeof(BIGNUM));
}

BIGNUM *
hk_bn_new(void)
{
	BIGNUM     *ret = NULL;

	if ((ret = hk_calloc(sizeof(BIGNUM))) == NULL) {
		return (NULL);
	}
	//ret->flags = BN_FLG_MALLOCED;

	return (ret);
}

void
hk_bn_clear_free(BIGNUM *a)
{
	//int i;

	if (a == NULL) {
		return;
    }

	if (a->d != NULL/* && !(BN_get_flags(a, BN_FLG_STATIC_DATA))*/) {
		memset(a->d, 0, a->dmax * sizeof(a->d[0]));
		hk_free(a->d);
	}
	//i = BN_get_flags(a, BN_FLG_MALLOCED);
	memset(a, 0, sizeof(*a));
	//if (i)
		hk_free(a);
}

void
hk_bn_free(BIGNUM *bn)
{
    hk_bn_clear_free(bn);
}

static BN_ULONG *
hk_bn_expand_internal(const BIGNUM *b, int words)
{
    BN_ULONG    *a = NULL;

    a = hk_calloc(words*sizeof(*a));
    if (a == NULL) {
        return NULL;
    }
	memcpy(a, b->d, sizeof(b->d[0]) * b->top);

    return a;
}

/* This is an internal function that should not be used in applications.
 * It ensures that 'b' has enough room for a 'words' word number
 * and initialises any unused part of b->d with leading zeros.
 * It is mostly used by the various BIGNUM routines. If there is an error,
 * NULL is returned. If not, 'b' is returned. */

BIGNUM *
hk_bn_expand2(BIGNUM *b, int words)
{
	hk_bn_check_top(b);

	if (words > b->dmax) {
		BN_ULONG *a = hk_bn_expand_internal(b, words);
		if (!a) {
			return NULL;
        }

		if (b->d) {
			memset(b->d, 0, b->dmax * sizeof(b->d[0]));
			hk_free(b->d);
		}
		b->d = a;
		b->dmax = words;
	}

	hk_bn_check_top(b);
	return b;
}

BIGNUM *
hk_bn_expand(BIGNUM *a, int bits)
{
	if (bits > (INT_MAX - HK_BN_BITS2 + 1))
		return (NULL);

	if (((bits + HK_BN_BITS2 - 1) / HK_BN_BITS2) <= a->dmax)
		return (a);

	return hk_bn_expand2(a, (bits + HK_BN_BITS2 - 1) / HK_BN_BITS2);
}

int
hk_bn_set_word(BIGNUM *a, BN_ULONG w)
{
	if (hk_bn_expand(a, (int)sizeof(BN_ULONG) * 8) == NULL) {
		return (0);
    }

	a->neg = 0;
	a->d[0] = w;
	a->top = (w ? 1 : 0);
	return (1);
}


BIGNUM *
hk_bn_bin2bn(const uint8_t *s, int len, BIGNUM *ret)
{
	BIGNUM      *bn = NULL;
	uint32_t    i = 0;
    uint32_t    m = 0;
	uint32_t    n = 0;
	BN_ULONG    l = 0;

	if (ret == NULL) {
		ret = bn = hk_bn_new();
    }

	if (ret == NULL) {
		return (NULL);
    }

	l = 0;
	n = len;
	if (n == 0) {
		ret->top = 0;
		return (ret);
	}
	i = ((n - 1) / HK_BN_BYTES) + 1;
	m = ((n - 1) % (HK_BN_BYTES));
	if (hk_bn_wexpand(ret, (int)i) == NULL) {
		hk_bn_free(bn);
		return NULL;
	}
	ret->top = i;
	ret->neg = 0;
	while (n--) {
		l = (l << 8L) | *(s++);
		if (m-- == 0) {
			ret->d[--i] = l;
			l = 0;
			m = HK_BN_BYTES - 1;
		}
	}
	/* need to call this due to clear byte at top if avoiding
	 * having the top bit set (-ve number) */
	hk_bn_correct_top(ret);
	return (ret);
}

/* ignore negative */
int
hk_bn_bn2bin(const BIGNUM *a, unsigned char *to)
{
	int n, i;
	BN_ULONG l;

	n = i = hk_bn_num_bytes(a);
	while (i--) {
		l = a->d[i / HK_BN_BYTES];
		*(to++) = (unsigned char)(l >> (8 * (i % HK_BN_BYTES))) & 0xff;
	}
	return (n);
}


int
hk_bn_ucmp(const BIGNUM *a, const BIGNUM *b)
{
	int         i;
	BN_ULONG t1, t2, *ap, *bp;

	bn_check_top(a);
	bn_check_top(b);

	i = a->top - b->top;
	if (i != 0)
		return (i);
	ap = a->d;
	bp = b->d;
	for (i = a->top - 1; i >= 0; i--) {
		t1 = ap[i];
		t2 = bp[i];
		if (t1 != t2)
			return ((t1 > t2) ? 1 : -1);
	}

	return (0);
}


int
hk_bn_num_bits_word(BN_ULONG l)
{
	static const unsigned char bits[256] = {
		0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
		5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
		6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
		6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	};

	if (l & 0xffffffff00000000L) {
		if (l & 0xffff000000000000L) {
			if (l & 0xff00000000000000L) {
				return (bits[(int)(l >> 56)] + 56);
			}
			return (bits[(int)(l >> 48)] + 48);
		} else {
			if (l & 0x0000ff0000000000L) {
				return (bits[(int)(l >> 40)] + 40);
			} 
		    return (bits[(int)(l >> 32)] + 32);
		}
	} else {
		if (l & 0xffff0000L) {
			if (l & 0xff000000L) {
				return (bits[(int)(l >> 24L)] + 24);
            }
			return (bits[(int)(l >> 16L)] + 16);
		} else {
			if (l & 0xff00L) {
				return (bits[(int)(l >> 8)] + 8);
            }
			return (bits[(int)(l)]);
		}
	}
}

int
hk_bn_num_bits(const BIGNUM *a)
{
	int     i = a->top - 1;

	hk_bn_check_top(a);

	if (hk_bn_is_zero(a)) {
		return 0;
    }

	return ((i * HK_BN_BITS2) + hk_bn_num_bits_word(a->d[i]));
}

