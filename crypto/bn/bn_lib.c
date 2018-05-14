#include <string.h>

#include <falcontls/bn.h>
#include <falcontls/crypto.h>
#include <internal/bn.h>

#include "bn_lcl.h"

#if !defined(SIXTY_FOUR_BIT_LONG)
#include <openssl/bn.h>
#endif

void
FC_BN_init(FC_BIGNUM *a)
{
	memset(a, 0, sizeof(FC_BIGNUM));
}

FC_BIGNUM *
FC_BN_new(void)
{
	FC_BIGNUM     *ret = NULL;

	if ((ret = FALCONTLS_calloc(sizeof(FC_BIGNUM))) == NULL) {
		return (NULL);
	}
	ret->flags = FC_BN_FLG_MALLOCED;

	return (ret);
}

void
FC_BN_clear_free(FC_BIGNUM *a)
{
	int     i = 0;

	if (a == NULL) {
		return;
    }

	if (a->d != NULL/* && !(BN_get_flags(a, BN_FLG_STATIC_DATA))*/) {
		memset(a->d, 0, a->dmax * sizeof(a->d[0]));
		FALCONTLS_free(a->d);
	}
	i = FC_BN_get_flags(a, FC_BN_FLG_MALLOCED);
	memset(a, 0, sizeof(*a));
	if (i) {
		FALCONTLS_free(a);
    }
}

void
FC_BN_free(FC_BIGNUM *bn)
{
    FC_BN_clear_free(bn);
}

static FC_BN_ULONG *
FC_BN_expand_internal(const FC_BIGNUM *b, int words)
{
    FC_BN_ULONG    *a = NULL;

    a = FALCONTLS_calloc(words*sizeof(*a));
    if (a == NULL) {
        return NULL;
    }
	memcpy(a, b->d, sizeof(b->d[0]) * b->top);

    return a;
}

/* This is an internal function that should not be used in applications.
 * It ensures that 'b' has enough room for a 'words' word number
 * and initialises any unused part of b->d with leading zeros.
 * It is mostly used by the various FC_BIGNUM routines. If there is an error,
 * NULL is returned. If not, 'b' is returned. */

FC_BIGNUM *
FC_BN_expand2(FC_BIGNUM *b, int words)
{
	FC_BN_check_top(b);

	if (words > b->dmax) {
		FC_BN_ULONG *a = FC_BN_expand_internal(b, words);
		if (!a) {
			return NULL;
        }

		if (b->d) {
			memset(b->d, 0, b->dmax * sizeof(b->d[0]));
			FALCONTLS_free(b->d);
		}
		b->d = a;
		b->dmax = words;
	}

	FC_BN_check_top(b);
	return b;
}

FC_BIGNUM *
FC_BN_expand(FC_BIGNUM *a, int bits)
{
	if (bits > (INT_MAX - FC_BN_BITS2 + 1))
		return (NULL);

	if (((bits + FC_BN_BITS2 - 1) / FC_BN_BITS2) <= a->dmax)
		return (a);

	return FC_BN_expand2(a, (bits + FC_BN_BITS2 - 1) / FC_BN_BITS2);
}

int
FC_BN_set_word(FC_BIGNUM *a, FC_BN_ULONG w)
{
	if (FC_BN_expand(a, (int)sizeof(FC_BN_ULONG) * 8) == NULL) {
		return (0);
    }

	a->neg = 0;
	a->d[0] = w;
	a->top = (w ? 1 : 0);
	return (1);
}


FC_BIGNUM *
FC_BN_bin2bn(const uint8_t *s, int len, FC_BIGNUM *ret)
{
	FC_BIGNUM      *bn = NULL;
	uint32_t    i = 0;
    uint32_t    m = 0;
	uint32_t    n = 0;
	FC_BN_ULONG    l = 0;

	if (ret == NULL) {
		ret = bn = FC_BN_new();
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
	i = ((n - 1) / FC_BN_BYTES) + 1;
	m = ((n - 1) % (FC_BN_BYTES));
	if (FC_BN_wexpand(ret, (int)i) == NULL) {
		FC_BN_free(bn);
		return NULL;
	}
	ret->top = i;
	ret->neg = 0;
	while (n--) {
		l = (l << 8L) | *(s++);
		if (m-- == 0) {
			ret->d[--i] = l;
			l = 0;
			m = FC_BN_BYTES - 1;
		}
	}
	/* need to call this due to clear byte at top if avoiding
	 * having the top bit set (-ve number) */
	FC_BN_correct_top(ret);
	return (ret);
}

/* ignore negative */
int
FC_BN_bn2bin(const FC_BIGNUM *a, unsigned char *to)
{
	int n, i;
	FC_BN_ULONG l;

	n = i = FC_BN_num_bytes(a);
	while (i--) {
		l = a->d[i / FC_BN_BYTES];
		*(to++) = (unsigned char)(l >> (8 * (i % FC_BN_BYTES))) & 0xff;
	}
	return (n);
}


int
FC_BN_ucmp(const FC_BIGNUM *a, const FC_BIGNUM *b)
{
	int         i;
	FC_BN_ULONG t1, t2, *ap, *bp;

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
FC_BN_num_bits_word(FC_BN_ULONG l)
{
#if defined(SIXTY_FOUR_BIT_LONG)
	static const fc_u8 bits[256] = {
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
#else
    return BN_num_bits_word(l);
#endif
}

int
FC_BN_num_bits(const FC_BIGNUM *a)
{
	int     i = a->top - 1;

	FC_BN_check_top(a);

	if (FC_BN_is_zero(a)) {
		return 0;
    }

	return ((i * FC_BN_BITS2) + FC_BN_num_bits_word(a->d[i]));
}

