#ifndef __FC_BN_LCL_H__
#define __FC_BN_LCL_H__

#define FC_BN_check_top(a) 

#define FC_BN_FLG_MALLOCED      0x01
#define FC_BN_wexpand(a, words) \
    (((words) <= (a)->dmax)?(a):FC_BN_expand2((a),(words)))
extern FC_BIGNUM *FC_BN_expand2(FC_BIGNUM *b, int words);

#define FC_BN_correct_top(a) \
{ \
    FC_BN_ULONG     *ftl = NULL; \
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
