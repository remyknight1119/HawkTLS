

#include "hk_test.h"

int
hk_test_all(kh_test_func array, int num)
{
    int     i = 0;

    for (i = 0; i < num; i++) {
        if (array() != 0) {
            return -1;
        }
        array++;
    }

    return 0;
}
