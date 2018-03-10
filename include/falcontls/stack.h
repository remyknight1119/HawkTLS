#ifndef __FC_STACK_H__
#define __FC_STACK_H__

typedef struct stack_t FCTLS_STACK; /* Use STACK_OF(...) instead */

typedef int (*FCTLS_sk_compfunc)(const void *, const void *);
typedef void (*FCTLS_sk_freefunc)(void *);
typedef void *(*FCTLS_sk_copyfunc)(const void *);

int FCTLS_sk_num(const FCTLS_STACK *);
void *FCTLS_sk_value(const FCTLS_STACK *, int);

void *FCTLS_sk_set(FCTLS_STACK *st, int i, const void *data);

FCTLS_STACK *FCTLS_sk_new(FCTLS_sk_compfunc cmp);
FCTLS_STACK *FCTLS_sk_new_null(void);
void FCTLS_sk_free(FCTLS_STACK *);
void FCTLS_sk_pop_free(FCTLS_STACK *st, void (*func) (void *));
FCTLS_STACK *FCTLS_sk_deep_copy(const FCTLS_STACK *,
            FCTLS_sk_copyfunc c, FCTLS_sk_freefunc f);
int FCTLS_sk_insert(FCTLS_STACK *sk, const void *data, int where);
void *FCTLS_sk_delete(FCTLS_STACK *st, int loc);
void *FCTLS_sk_delete_ptr(FCTLS_STACK *st, const void *p);
int FCTLS_sk_find(FCTLS_STACK *st, const void *data);
int FCTLS_sk_find_ex(FCTLS_STACK *st, const void *data);
int FCTLS_sk_push(FCTLS_STACK *st, const void *data);
int FCTLS_sk_unshift(FCTLS_STACK *st, const void *data);
void *FCTLS_sk_shift(FCTLS_STACK *st);
void *FCTLS_sk_pop(FCTLS_STACK *st);
void FCTLS_sk_zero(FCTLS_STACK *st);
FCTLS_sk_compfunc FCTLS_sk_set_cmp_func(FCTLS_STACK *sk,
            FCTLS_sk_compfunc cmp);
FCTLS_STACK *FCTLS_sk_dup(const FCTLS_STACK *st);
void FCTLS_sk_sort(FCTLS_STACK *st);
int FCTLS_sk_is_sorted(const FCTLS_STACK *st);

#endif
