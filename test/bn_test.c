#include <stdio.h>

#include "hawktls/hk_bn.h"
#include "hk_lib.h"
#include "hk_test.h"

static int test_add(void);

static kh_test_func bn_test_array[] = {
    test_add,
};

#define BN_TEST_ARRAY_NUM HK_ARRAY_SIZE(bn_test_array)

static int
test_add(void)
{
    //hk_bn_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
    fprintf(stderr, "test add ok!\n");
    return 0;
}

int
main(int argc, char *argv[])
{
    return hk_test_all(bn_test_array[0], BN_TEST_ARRAY_NUM);
}
