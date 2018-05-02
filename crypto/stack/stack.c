#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include <falcontls/stack.h>
#include <falcontls/objects.h>
#include <falcontls/crypto.h>
#include <fc_log.h>

struct stack_t {
    int                 sk_num;
    const char          **sk_data;
    int                 sk_sorted;
    size_t              sk_num_alloc;
    FCTLS_sk_compfunc   sk_comp;
};

#undef MIN_NODES
#define MIN_NODES       4


FCTLS_sk_compfunc
FCTLS_sk_set_cmp_func(FCTLS_STACK *sk, FCTLS_sk_compfunc c)
{
    FCTLS_sk_compfunc   old = sk->sk_comp;

    if (sk->sk_comp != c) {
        sk->sk_sorted = 0;
    }
    sk->sk_comp = c;

    return old;
}

FCTLS_STACK *
FCTLS_sk_dup(const FCTLS_STACK *sk)
{
    FCTLS_STACK     *ret = NULL;

    if (sk->sk_num < 0) {
        return NULL;
    }

    if ((ret = FALCONTLS_malloc(sizeof(*ret))) == NULL) {
        return NULL;
    }

    /* direct structure assignment */
    *ret = *sk;

    if ((ret->sk_data = FALCONTLS_malloc(sizeof(*ret->sk_data) *
                    sk->sk_num_alloc)) == NULL) {
        goto err;
    }
    memcpy(ret->sk_data, sk->sk_data, sizeof(char *) * sk->sk_num);
    return ret;
 err:
    FCTLS_sk_free(ret);
    return NULL;
}

FCTLS_STACK *
FCTLS_sk_deep_copy(const FCTLS_STACK *sk,
                        FCTLS_sk_copyfunc copy_func,
                        FCTLS_sk_freefunc free_func)
{
    FCTLS_STACK     *ret = NULL;
    int             i = 0;

    if (sk->sk_num < 0) {
        return NULL;
    }

    if ((ret = FALCONTLS_malloc(sizeof(*ret))) == NULL) {
        return NULL;
    }

    /* direct structure assignment */
    *ret = *sk;

    ret->sk_num_alloc = sk->sk_num > MIN_NODES ? (size_t)sk->sk_num : MIN_NODES;
    ret->sk_data = FALCONTLS_calloc(sizeof(*ret->sk_data) * ret->sk_num_alloc);
    if (ret->sk_data == NULL) {
        FALCONTLS_free(ret);
        return NULL;
    }

    for (i = 0; i < ret->sk_num; ++i) {
        if (sk->sk_data[i] == NULL) {
            continue;
        }
        if ((ret->sk_data[i] = copy_func(sk->sk_data[i])) == NULL) {
            while (--i >= 0) {
                if (ret->sk_data[i] != NULL) {
                    free_func((void *)ret->sk_data[i]);
                }
            }
            FCTLS_sk_free(ret);
            return NULL;
        }
    }
    return ret;
}

FCTLS_STACK *
FCTLS_sk_new_null(void)
{
    return FCTLS_sk_new((FCTLS_sk_compfunc)NULL);
}

FCTLS_STACK *
FCTLS_sk_new(FCTLS_sk_compfunc c)
{
    FCTLS_STACK     *ret = NULL;

    if ((ret = FALCONTLS_calloc(sizeof(*ret))) == NULL) {
        goto err;
    }
    ret->sk_data = FALCONTLS_calloc(sizeof(*ret->sk_data) * MIN_NODES);
    if (ret->sk_data == NULL) {
        goto err;
    }

    FC_LOG("comp = %p\n", c);
    ret->sk_comp = c;
    ret->sk_num_alloc = MIN_NODES;

    return (ret);

 err:
    FALCONTLS_free(ret);
    return (NULL);
}

int
FCTLS_sk_insert(FCTLS_STACK *st, const void *data, int loc)
{
    if (st == NULL || st->sk_num < 0 || st->sk_num == INT_MAX) {
        return 0;
    }

    if (st->sk_num_alloc <= (size_t)(st->sk_num + 1)) {
        size_t doub_num_alloc = st->sk_num_alloc * 2;
        const char **tmpdata;

        /* Overflow checks */
        if (doub_num_alloc < st->sk_num_alloc) {
            return 0;
        }

        /* Avoid overflow due to multiplication by sizeof(char *) */
        if (doub_num_alloc > SIZE_MAX / sizeof(char *)) {
            return 0;
        }

        tmpdata = FALCONTLS_realloc((char *)st->sk_data,
                                  sizeof(char *) * doub_num_alloc);
        if (tmpdata == NULL) {
            return 0;
        }

        st->sk_data = tmpdata;
        st->sk_num_alloc = doub_num_alloc;
    }
    if ((loc >= st->sk_num) || (loc < 0)) {
        st->sk_data[st->sk_num] = data;
    } else {
        memmove(&st->sk_data[loc + 1], &st->sk_data[loc],
                sizeof(st->sk_data[0]) * (st->sk_num - loc));
        st->sk_data[loc] = data;
    }
    st->sk_num++;
    st->sk_sorted = 0;

    return st->sk_num;
}

void *
FCTLS_sk_delete_ptr(FCTLS_STACK *st, const void *p)
{
    int     i = 0;

    for (i = 0; i < st->sk_num; i++) {
        if (st->sk_data[i] == p) {
            return FCTLS_sk_delete(st, i);
        }
    }

    return NULL;
}

void *
FCTLS_sk_delete(FCTLS_STACK *st, int loc)
{
    const char  *ret = NULL;

    if (st == NULL || loc < 0 || loc >= st->sk_num) {
        return NULL;
    }

    ret = st->sk_data[loc];
    if (loc != st->sk_num - 1) {
         memmove(&st->sk_data[loc], &st->sk_data[loc + 1],
                 sizeof(st->sk_data[0]) * (st->sk_num - loc - 1));
    }
    st->sk_num--;
    return (void *)ret;
}

static const void  *
obj_bsearch(const void *data, const char **sk_data, int sk_num,
            FCTLS_sk_compfunc comp)
{
    int             i = 0;

    for (i = 0; i < sk_num; i++) {
        if (comp(sk_data[i], data) == 0) {
            return (void *)&sk_data[i];
        }
    }

    return NULL;
}

static int
internal_find(FCTLS_STACK *st, const void *data,
                         int ret_val_options)
{
    const void      *r = NULL;
    int             i = 0;

    if (st == NULL) {
        return -1;
    }

    if (st->sk_comp == NULL) {
        for (i = 0; i < st->sk_num; i++) {
            if (st->sk_data[i] == data) {
                return (i);
            }
        }
        return (-1);
    }
    FCTLS_sk_sort(st);
    if (data == NULL) {
        return (-1);
    }

    r = obj_bsearch(data, st->sk_data, st->sk_num, st->sk_comp);
    if (r == NULL) {
        return (-1);
    }
    return (int)((const char **)r - st->sk_data);
}

int
FCTLS_sk_find(FCTLS_STACK *st, const void *data)
{
    return internal_find(st, data, FC_OBJ_BSEARCH_FIRST_VALUE_ON_MATCH);
}

int
FCTLS_sk_find_ex(FCTLS_STACK *st, const void *data)
{
    return internal_find(st, data, FC_OBJ_BSEARCH_VALUE_ON_NOMATCH);
}

int
FCTLS_sk_push(FCTLS_STACK *st, const void *data)
{
    return (FCTLS_sk_insert(st, data, st->sk_num));
}

int
FCTLS_sk_unshift(FCTLS_STACK *st, const void *data)
{
    return (FCTLS_sk_insert(st, data, 0));
}

void 
*FCTLS_sk_shift(FCTLS_STACK *st)
{
    if (st == NULL) {
        return (NULL);
    }
    if (st->sk_num <= 0) {
        return (NULL);
    }
    return (FCTLS_sk_delete(st, 0));
}

void *
FCTLS_sk_pop(FCTLS_STACK *st)
{
    if (st == NULL) {
        return (NULL);
    }
    if (st->sk_num <= 0) {
        return (NULL);
    }
    return (FCTLS_sk_delete(st, st->sk_num - 1));
}

void FCTLS_sk_zero(FCTLS_STACK *st)
{
    if (st == NULL) {
        return;
    }
    if (st->sk_num <= 0) {
        return;
    }
    memset(st->sk_data, 0, sizeof(*st->sk_data) * st->sk_num);
    st->sk_num = 0;
}

void FCTLS_sk_pop_free(FCTLS_STACK *st, FCTLS_sk_freefunc func)
{
    int     i = 0;

    if (st == NULL) {
        return;
    }
    for (i = 0; i < st->sk_num; i++) {
        if (st->sk_data[i] != NULL) {
            func((char *)st->sk_data[i]);
        }
    }
    FCTLS_sk_free(st);
}

void FCTLS_sk_free(FCTLS_STACK *st)
{
    if (st == NULL) {
        return;
    }
    FALCONTLS_free(st->sk_data);
    FALCONTLS_free(st);
}

int FCTLS_sk_num(const FCTLS_STACK *st)
{
    if (st == NULL) {
        return -1;
    }
    return st->sk_num;
}

void *FCTLS_sk_value(const FCTLS_STACK *st, int i)
{
    if (st == NULL || i < 0 || i >= st->sk_num) {
        return NULL;
    }
    return (void *)st->sk_data[i];
}

void *FCTLS_sk_set(FCTLS_STACK *st, int i, const void *data)
{
    if (st == NULL || i < 0 || i >= st->sk_num) {
        return NULL;
    }
    st->sk_data[i] = data;
    return (void *)st->sk_data[i];
}

void FCTLS_sk_sort(FCTLS_STACK *st)
{
    if (st && !st->sk_sorted && st->sk_comp != NULL) {
        qsort(st->sk_data, st->sk_num, sizeof(char *), st->sk_comp);
        st->sk_sorted = 1;
    }
}

int FCTLS_sk_is_sorted(const FCTLS_STACK *st)
{
    if (st == NULL) {
        return 1;
    }
    return st->sk_sorted;
}
