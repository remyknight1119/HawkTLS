#ifndef __FC_SAFESTACK_H__
#define __FC_SAFESTACK_H__

#include <falcontls/stack.h>

#define FC_STACK_OF(type) struct fc_stack_t_##type
//#define PREDECLARE_STACK_OF(type) FC_STACK_OF(type);

#define FC_SKM_DEFINE_STACK_OF(t1, t2, t3) \
    FC_STACK_OF(t1); \
    typedef int (*sk_##t1##_compfunc)(const t3 * const *a, const t3 *const *b); \
    typedef void (*sk_##t1##_freefunc)(t3 *a); \
    typedef t3 * (*sk_##t1##_copyfunc)(const t3 *a); \
    static inline int \
    sk_##t1##_num(const FC_STACK_OF(t1) *sk) \
    { \
        return FCTLS_sk_num((const FCTLS_STACK *)sk); \
    } \
    static inline t2 * \
    sk_##t1##_value(const FC_STACK_OF(t1) *sk, int idx) \
    { \
        return (t2 *)FCTLS_sk_value((const FCTLS_STACK *)sk, idx); \
    } \
    static inline FC_STACK_OF(t1) * \
    sk_##t1##_new(sk_##t1##_compfunc compare) \
    { \
        return (FC_STACK_OF(t1) *)FCTLS_sk_new((FCTLS_sk_compfunc)compare); \
    } \
    static inline FC_STACK_OF(t1) * \
    sk_##t1##_new_null(void) \
    { \
        return (FC_STACK_OF(t1) *)FCTLS_sk_new_null(); \
    } \
    static inline void \
    sk_##t1##_free(FC_STACK_OF(t1) *sk) \
    { \
        FCTLS_sk_free((FCTLS_STACK *)sk); \
    } \
    static inline void \
    sk_##t1##_zero(FC_STACK_OF(t1) *sk) \
    { \
        FCTLS_sk_zero((FCTLS_STACK *)sk); \
    } \
    static inline t2 * \
    sk_##t1##_delete(FC_STACK_OF(t1) *sk, int i) \
    { \
        return (t2 *)FCTLS_sk_delete((FCTLS_STACK *)sk, i); \
    } \
    static inline t2 * \
    sk_##t1##_delete_ptr(FC_STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return (t2 *)FCTLS_sk_delete_ptr((FCTLS_STACK *)sk, \
                                           (const void *)ptr); \
    } \
    static inline int \
    sk_##t1##_push(FC_STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return FCTLS_sk_push((FCTLS_STACK *)sk, (const void *)ptr); \
    } \
    static inline int \
    sk_##t1##_unshift(FC_STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return FCTLS_sk_unshift((FCTLS_STACK *)sk, (const void *)ptr); \
    } \
    static inline t2 * \
    sk_##t1##_pop(FC_STACK_OF(t1) *sk) \
    { \
        return (t2 *)FCTLS_sk_pop((FCTLS_STACK *)sk); \
    } \
    static inline t2 * \
    sk_##t1##_shift(FC_STACK_OF(t1) *sk) \
    { \
        return (t2 *)FCTLS_sk_shift((FCTLS_STACK *)sk); \
    } \
    static inline void \
    sk_##t1##_pop_free(FC_STACK_OF(t1) *sk, sk_##t1##_freefunc freefunc) \
    { \
        FCTLS_sk_pop_free((FCTLS_STACK *)sk, (FCTLS_sk_freefunc)freefunc); \
    } \
    static inline int \
    sk_##t1##_insert(FC_STACK_OF(t1) *sk, t2 *ptr, int idx) \
    { \
        return FCTLS_sk_insert((FCTLS_STACK *)sk, (const void *)ptr, idx); \
    } \
    static inline t2 * \
    sk_##t1##_set(FC_STACK_OF(t1) *sk, int idx, t2 *ptr) \
    { \
        return (t2 *)FCTLS_sk_set((FCTLS_STACK *)sk, idx, (const void *)ptr); \
    } \
    static inline int \
    sk_##t1##_find(FC_STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return FCTLS_sk_find((FCTLS_STACK *)sk, (const void *)ptr); \
    } \
    static inline int \
    sk_##t1##_find_ex(FC_STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return FCTLS_sk_find_ex((FCTLS_STACK *)sk, (const void *)ptr); \
    } \
    static inline void \
    sk_##t1##_sort(FC_STACK_OF(t1) *sk) \
    { \
        FCTLS_sk_sort((FCTLS_STACK *)sk); \
    } \
    static inline int \
    sk_##t1##_is_sorted(const FC_STACK_OF(t1) *sk) \
    { \
        return FCTLS_sk_is_sorted((const FCTLS_STACK *)sk); \
    } \
    static inline FC_STACK_OF(t1) * \
    sk_##t1##_dup(const FC_STACK_OF(t1) *sk) \
    { \
        return (FC_STACK_OF(t1) *)FCTLS_sk_dup((const FCTLS_STACK *)sk); \
    } \
    static inline FC_STACK_OF(t1) * \
    sk_##t1##_deep_copy(const FC_STACK_OF(t1) *sk, \
                            sk_##t1##_copyfunc copyfunc, \
                            sk_##t1##_freefunc freefunc) \
    { \
        return (FC_STACK_OF(t1) *)FCTLS_sk_deep_copy((const FCTLS_STACK *)sk, \
                                            (FCTLS_sk_copyfunc)copyfunc, \
                                            (FCTLS_sk_freefunc)freefunc); \
    } \
    static inline sk_##t1##_compfunc \
    sk_##t1##_set_cmp_func(FC_STACK_OF(t1) *sk, sk_##t1##_compfunc compare) \
    { \
        return (sk_##t1##_compfunc)FCTLS_sk_set_cmp_func((FCTLS_STACK *)sk, \
                (FCTLS_sk_compfunc)compare); \
    }

#define FC_DEFINE_SPECIAL_STACK_OF(t1, t2) FC_SKM_DEFINE_STACK_OF(t1, t2, t2)
#define FC_DEFINE_STACK_OF(t) FC_SKM_DEFINE_STACK_OF(t, t, t)
#define FC_DEFINE_SPECIAL_STACK_OF_CONST(t1, t2) \
            FC_SKM_DEFINE_STACK_OF(t1, const t2, t2)
#define FC_DEFINE_STACK_OF_CONST(t) FC_SKM_DEFINE_STACK_OF(t, const t, t)



#endif
