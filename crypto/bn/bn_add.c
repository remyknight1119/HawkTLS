#include <stdio.h>

#include <falcontls/types.h>
#include <falcontls/bn.h>
#include <internal/bn.h>

#include "bn_lcl.h"

int
FC_BN_uadd(FC_BIGNUM *r, const FC_BIGNUM *a, const FC_BIGNUM *b)
{
    const FC_BIGNUM     *tmp = NULL;
    FC_BN_ULONG         *ap = NULL;
    FC_BN_ULONG         *bp = NULL;
    FC_BN_ULONG         *rp = NULL;
    FC_BN_ULONG         carry = 0;
    FC_BN_ULONG         t1 = 0;
    FC_BN_ULONG         t2 = 0;
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

	if (FC_BN_wexpand(r, max + 1) == NULL) {
		return 0;
    }

	r->top = max;

	ap = a->d;
	bp = b->d;
	rp = r->d;

	carry = FC_BN_add_words(rp, ap, bp, min);
	rp += min;
	ap += min;
	bp += min;

	if (carry) {
		while (dif) {
			dif--;
			t1 = *(ap++);
			t2 = (t1 + 1) & FC_BN_MASK2;
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
