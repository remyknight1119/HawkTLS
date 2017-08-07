#include <stdio.h>

#include "hawktls/hk_bn.h"
#include "hk_bn_lcl.h"

int
hk_bn_uadd(HK_BIGNUM *r, const HK_BIGNUM *a, const HK_BIGNUM *b)
{
    const HK_BIGNUM     *tmp = NULL;
    HK_BN_ULONG         *ap = NULL;
    HK_BN_ULONG         *bp = NULL;
    HK_BN_ULONG         *rp = NULL;
    HK_BN_ULONG         carry = 0;
    HK_BN_ULONG         t1 = 0;
    HK_BN_ULONG         t2 = 0;
    int                 max = 0;
    int                 min = 0;
    int                 dif = 0;

    if (a->top < b->top) {
		tmp = a;
		a = b;
		b = tmp;
	}
	max = a->top;
	min = b->top;
	dif = max - min;

	if (hk_bn_wexpand(r, max + 1) == NULL) {
		return 0;
    }

	r->top = max;

	ap = a->d;
	bp = b->d;
	rp = r->d;

	carry = hk_bn_add_words(rp, ap, bp, min);
	rp += min;
	ap += min;
	bp += min;

	if (carry) {
		while (dif) {
			dif--;
			t1 = *(ap++);
			t2 = (t1 + 1) & HK_BN_MASK2;
			*(rp++) = t2;
			if (t2) {
				carry = 0;
				break;
			}
		}
		if (carry) {
			/* carry != 0 => dif == 0 */
			*rp = 1;
			r->top++;
		}
	}

	if (dif && rp != ap) {
		while (dif--)
			/* copy remaining words if ap != rp */
			*(rp++) = *(ap++);
    }

	r->neg = 0;

    return 1;
}
