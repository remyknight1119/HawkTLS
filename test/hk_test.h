#ifndef __HK_TEST_H__
#define __HK_TEST_H__

typedef int (*kh_test_func)(void);

extern int hk_test_all(kh_test_func array, int num);

#endif
