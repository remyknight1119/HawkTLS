#include <stdio.h>
#include <openssl/bn.h>

#include "hawktls/hk_bn.h"
#include "hk_lib.h"
#include "hk_test.h"
#include "hk_print.h"

static unsigned char bn_a[] =
    "\x00\xAA\x36\xAB\xCE\x88\xAC\xFD\xFF\x55\x52\x3C\x7F\xC4\x52\x3F"
    "\x90\xEF\xA0\x0D\xF3\x77\x4A\x25\x9F\x2E\x62\xB4\xC5\xD9\x9C\xB5"
    "\xAD\xB3\x00\xA0\x28\x5E\x53\x01\x93\x0E\x0C\x70\xFB\x68\x76\x93"
    "\x9C\xE6\x16\xCE\x62\x4A\x11\xE0\x08\x6D\x34\x1E\xBC\xAC\xA0\xA1"
    "\xF5";

static unsigned char bn_b[] =
    "\x00\xBB\xF8\x2F\x09\x06\x82\xCE\x9C\x23\x38\xAC\x2B\x9D\xA8\x71"
    "\xF7\x36\x8D\x07\xEE\xD4\x10\x43\xA4\x40\xD6\xB6\xF0\x74\x54\xF5"
    "\x1F\xB8\xDF\xBA\xAF\x03\x5C\x02\xAB\x61\xEA\x48\xCE\xEB\x6F\xCD"
    "\x48\x76\xED\x52\x0D\x60\xE1\xEC\x46\x19\x71\x9D\x8A\x5B\x8B\x80"
    "\x7F\xAF\xB8\xE0\xA3\xDF\xC7\x37\x72\x3E\xE6\xB4\xB7\xD9\x3A\x25"
    "\x84\xEE\x6A\x64\x9D\x06\x09\x53\x74\x88\x34\xB2\x45\x45\x98\x39"
    "\x4E\xE0\xAA\xB1\x2D\x7B\x61\xA5\x1F\x52\x7A\x9A\x41\xF6\xC1\x68"
    "\x7F\xE2\x53\x72\x98\xCA\x2A\x8F\x59\x46\xF8\xE5\xFD\x09\x1D\xBD"
    "\xCB";


static int test_add(void);

static kh_test_func bn_test_array[] = {
    test_add,
};

#define BN_TEST_ARRAY_NUM HK_ARRAY_SIZE(bn_test_array)

static int
test_add(void)
{
    BIGNUM      *a = NULL;
    BIGNUM      *b = NULL;
    HK_BIGNUM   *ah = NULL;
    HK_BIGNUM   *bh = NULL;
    uint8_t     *d = NULL;
    uint8_t     *dh = NULL;
    BIGNUM      r = {};
    HK_BIGNUM   rh = {};
    int         dlen = 0;

    a = BN_bin2bn(bn_a, sizeof(bn_a) - 1, a);
    if (a == NULL) {
        fprintf(stderr, "BN_bin2bn failed!\n");
        return -1;
    }

    b = BN_bin2bn(bn_b, sizeof(bn_b) - 1, b);
    if (b == NULL) {
        fprintf(stderr, "BN_bin2bn failed!\n");
        return -1;
    }

    if (!BN_uadd(&r, a, b)) {
        fprintf(stderr, "BN_uadd failed!\n");
        return -1;
    }

    ah = hk_bn_bin2bn(bn_a, sizeof(bn_a) - 1, ah);
    if (ah == NULL) {
        fprintf(stderr, "BN_bin2bn failed!\n");
        return -1;
    }

    bh = hk_bn_bin2bn(bn_b, sizeof(bn_b) - 1, bh);
    if (bh == NULL) {
        fprintf(stderr, "BN_bin2bn failed!\n");
        return -1;
    }

    if (!hk_bn_uadd(&rh, ah, bh)) {
        fprintf(stderr, "hk_bn_uadd failed!\n");
        return -1;
    }
 
    dlen = HK_MAX(sizeof(bn_a), sizeof(bn_b));
    d = malloc(dlen);
    if (d == NULL) {
        fprintf(stderr, "Malloc d failed!\n");
        return -1;
    }

    BN_bn2bin(&r, d);
    hk_print(d, dlen);
    dh = malloc(dlen);
    if (dh == NULL) {
        fprintf(stderr, "Malloc d failed!\n");
        return -1;
    }

    hk_bn_bn2bin(&rh, dh);
    hk_print(dh, dlen);
    free(dh);
    free(d);
    //hk_bn_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
    fprintf(stderr, "test add ok!\n");
    hk_bn_free(&rh);
    hk_bn_free(bh);
    hk_bn_free(ah);
    BN_free(&r);
    BN_free(b);
    BN_free(a);

    return 0;
}

int
main(int argc, char *argv[])
{
    return hk_test_all(bn_test_array[0], BN_TEST_ARRAY_NUM);
}
