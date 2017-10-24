

#include <hawktls/hk_bn.h>
#include "hk_assert.h"

HK_BN_ULONG
hk_bn_add_words(HK_BN_ULONG *r, const HK_BN_ULONG *a, const HK_BN_ULONG *b, int n)
{
	HK_BN_ULONG     c = 0;
    HK_BN_ULONG     l = 0;
    HK_BN_ULONG     t = 0;

	hk_assert(n >= 0);
	if (n <= 0) {
		return 0;
    }

	c = 0;

	while (n) {
		t = a[0];
		t = (t + c) & HK_BN_MASK2;
		c = (t < c);
		l = (t + b[0]) & HK_BN_MASK2;
		c += (l < t);
		r[0] = l;
		a++;
		b++;
		r++;
		n--;
	}

	return c;
}
