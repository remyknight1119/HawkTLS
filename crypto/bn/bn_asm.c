

#include <falcontls/bn.h>

#include <fc_assert.h>

FC_BN_ULONG
FC_BN_add_words(FC_BN_ULONG *r, const FC_BN_ULONG *a, const FC_BN_ULONG *b, int n)
{
	FC_BN_ULONG     c = 0;
    FC_BN_ULONG     l = 0;
    FC_BN_ULONG     t = 0;

	fc_assert(n >= 0);
	if (n <= 0) {
		return 0;
    }

	c = 0;

	while (n) {
		t = a[0];
		t = (t + c) & FC_BN_MASK2;
		c = (t < c);
		l = (t + b[0]) & FC_BN_MASK2;
		c += (l < t);
		r[0] = l;
		a++;
		b++;
		r++;
		n--;
	}

	return c;
}
