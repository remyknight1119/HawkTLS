#ifndef __HK_BN_LCL_H__
#define __HK_BN_LCL_H__

#define hk_bn_check_top(a) 

#define HK_BN_FLG_MALLOCED      0x01
#define hk_bn_wexpand(a, words) \
    (((words) <= (a)->dmax)?(a):hk_bn_expand2((a),(words)))
extern HK_BIGNUM *hk_bn_expand2(HK_BIGNUM *b, int words);

#define hk_bn_correct_top(a) \
{ \
    HK_BN_ULONG     *ftl = NULL; \
    int             tmp_top = (a)->top; \
    if (tmp_top > 0) {\
        for (ftl= &((a)->d[tmp_top - 1]); tmp_top > 0; tmp_top--) {\
            if (*(ftl--)) { \
                break; \
            } \
        } \
        (a)->top = tmp_top; \
    } \
}


#endif
