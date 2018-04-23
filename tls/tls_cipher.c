#include <string.h>

#include <falcontls/tls.h>
#include <falcontls/crypto.h>
#include <falcontls/x509.h>
#include <fc_log.h>

#include "tls1.h"
#include "tls_locl.h"

#define CIPHER_ADD      1
#define CIPHER_KILL     2
#define CIPHER_DEL      3
#define CIPHER_ORD      4
#define CIPHER_SPECIAL  5
/*
 * Bump the ciphers to the top of the list.
 * This rule isn't currently supported by the public cipherstring API.
 */
#define CIPHER_BUMP     6

typedef struct cipher_order_t {
    const TLS_CIPHER        *cipher;
    int                     active;
    int                     dead;
    struct cipher_order_t   *next;
    struct cipher_order_t   *prev;
} CIPHER_ORDER;

static void
tls_cipher_collect_ciphers(const TLS_METHOD *tls_method, int num_of_ciphers,
                            CIPHER_ORDER *co_list, CIPHER_ORDER **head_p,
                            CIPHER_ORDER **tail_p)
{
    const TLS_CIPHER    *c = NULL;
    int                 i = 0;
    int                 co_list_num = 0;

    /*
     * We have num_of_ciphers descriptions compiled in, depending on the
     * method selected (SSLv3, TLSv1 etc).
     * These will later be sorted in a linked list with at most num
     * entries.
     */

    /* Get the initial list of ciphers */
    co_list_num = 0;            /* actual count of ciphers */
    for (i = 0; i < num_of_ciphers; i++) {
        c = tls_method->md_get_cipher(i);
        if (c == NULL) {
            continue;
        }

        co_list[co_list_num].cipher = c;
        co_list[co_list_num].next = NULL;
        co_list[co_list_num].prev = NULL;
        co_list[co_list_num].active = 0;
        co_list_num++;
        /*
         * if (!sk_push(ca_list,(char *)c)) goto err;
         */
    }

    /*
     * Prepare linked list from list entries
     */
    if (co_list_num > 0) {
        co_list[0].prev = NULL;

        if (co_list_num > 1) {
            co_list[0].next = &co_list[1];

            for (i = 1; i < co_list_num - 1; i++) {
                co_list[i].prev = &co_list[i - 1];
                co_list[i].next = &co_list[i + 1];
            }

            co_list[co_list_num - 1].prev = &co_list[co_list_num - 2];
        }

        co_list[co_list_num - 1].next = NULL;

        *head_p = &co_list[0];
        *tail_p = &co_list[co_list_num - 1];
    }
}

static void
ll_append_tail(CIPHER_ORDER **head, CIPHER_ORDER *curr,
                           CIPHER_ORDER **tail)
{
    if (curr == *tail) {
        return;
    }
    if (curr == *head) {
        *head = curr->next;
    }
    if (curr->prev != NULL) {
        curr->prev->next = curr->next;
    }
    if (curr->next != NULL) {
        curr->next->prev = curr->prev;
    }
    (*tail)->next = curr;
    curr->prev = *tail;
    curr->next = NULL;
    *tail = curr;
}

static void
ll_append_head(CIPHER_ORDER **head, CIPHER_ORDER *curr,
                           CIPHER_ORDER **tail)
{
    if (curr == *head) {
        return;
    }
    if (curr == *tail) {
        *tail = curr->prev;
    }
    if (curr->next != NULL) {
        curr->next->prev = curr->prev;
    }
    if (curr->prev != NULL) {
        curr->prev->next = curr->next;
    }
    (*head)->prev = curr;
    curr->next = *head;
    curr->prev = NULL;
    *head = curr;
}

static int 
tls_cipher_strength_sort(CIPHER_ORDER **head_p, CIPHER_ORDER **tail_p)
{
    return 1;
}

static int
tls_cipher_process_rulestr(const char *rule_str, CIPHER_ORDER **head_p,
                                      CIPHER_ORDER **tail_p,
                                      const TLS_CIPHER **ca_list, CERT *c)
{
    return 1;
}

static void
tls_cipher_apply_rule(fc_u32 cipher_id, fc_u32 alg_mkey, fc_u32 alg_auth,
                        fc_u32 alg_enc, fc_u32 alg_mac, int min_tls,
                        fc_u32 algo_strength, int rule, int strength_bits,
                        CIPHER_ORDER **head_p, CIPHER_ORDER **tail_p)
{
    CIPHER_ORDER        *head = NULL;
    CIPHER_ORDER        *tail = NULL;
    CIPHER_ORDER        *curr = NULL;
    CIPHER_ORDER        *next = NULL;
    CIPHER_ORDER        *last = NULL;
    const TLS_CIPHER    *cp = NULL;
    int                 reverse = 0;

    fprintf(stderr,
            "Applying rule %d with %08x/%08x/%08x/%08x/%08x %08x (%d)\n",
            rule, alg_mkey, alg_auth, alg_enc, alg_mac, min_tls,
            algo_strength, strength_bits);

    if (rule == CIPHER_DEL || rule == CIPHER_BUMP) {
    /* needed to maintain sorting between currently deleted ciphers */
        reverse = 1;
    }

    head = *head_p;
    tail = *tail_p;

    if (reverse) {
        next = tail;
        last = head;
    } else {
        next = head;
        last = tail;
    }

    curr = NULL;
    for (;;) {
        if (curr == last) {
            break;
        }

        curr = next;
        if (curr == NULL) {
            break;
        }

        next = reverse ? curr->prev : curr->next;

        cp = curr->cipher;

        /*
         * Selection criteria is either the value of strength_bits
         * or the algorithms used.
         */
        if (strength_bits >= 0) {
            if (strength_bits != cp->cp_strength_bits) {
                continue;
            }
        } else {
            fprintf(stderr,
                    "\nName: %s:\nAlgo = %08x/%08x/%08x/%08x\n",
                    cp->cp_name, cp->cp_algorithm_mkey, cp->cp_algorithm_auth,
                    cp->cp_algorithm_enc, cp->cp_algorithm_mac);
            if (alg_mkey && !(alg_mkey & cp->cp_algorithm_mkey)) {
                continue;
            }
            if (alg_auth && !(alg_auth & cp->cp_algorithm_auth)) {
                continue;
            }
            if (alg_enc && !(alg_enc & cp->cp_algorithm_enc)) {
                continue;
            }
            if (alg_mac && !(alg_mac & cp->cp_algorithm_mac)) {
                continue;
            }
        }

        fprintf(stderr, "Action = %d\n", rule);

        /* add the cipher if it has not been added yet. */
        if (rule == CIPHER_ADD) {
            /* reverse == 0 */
            if (!curr->active) {
                ll_append_tail(&head, curr, &tail);
                curr->active = 1;
            }
        }
        /* Move the added cipher to this location */
        else if (rule == CIPHER_ORD) {
            /* reverse == 0 */
            if (curr->active) {
                ll_append_tail(&head, curr, &tail);
            }
        } else if (rule == CIPHER_DEL) {
            /* reverse == 1 */
            if (curr->active) {
                /*
                 * most recently deleted ciphersuites get best positions for
                 * any future CIPHER_ADD (note that the CIPHER_DEL loop works
                 * in reverse to maintain the order)
                 */
                ll_append_head(&head, curr, &tail);
                curr->active = 0;
            }
        } else if (rule == CIPHER_BUMP) {
            if (curr->active) {
                ll_append_head(&head, curr, &tail);
            }
        } else if (rule == CIPHER_KILL) {
            /* reverse == 0 */
            if (head == curr) {
                head = curr->next;
            } else {
                curr->prev->next = curr->next;
            }
            if (tail == curr) {
                tail = curr->prev;
            }
            curr->active = 0;
            if (curr->next != NULL) {
                curr->next->prev = curr->prev;
            }
            if (curr->prev != NULL) {
                curr->prev->next = curr->next;
            }
            curr->next = NULL;
            curr->prev = NULL;
        }
    }

    *head_p = head;
    *tail_p = tail;
}



FC_STACK_OF(TLS_CIPHER) *
tls_create_cipher_list(const TLS_METHOD *method, FC_STACK_OF(TLS_CIPHER) 
                        **cipher_list, FC_STACK_OF(TLS_CIPHER) 
                        **cipher_list_by_id, const char *rule_str,
                        CERT *c)
{
    const TLS_CIPHER            **ca_list = NULL;
    FC_STACK_OF(TLS_CIPHER)     *cipherstack = NULL;
    FC_STACK_OF(TLS_CIPHER)     *tmp_cipher_list = NULL;
    const char                  *rule_p = NULL;
    CIPHER_ORDER                *co_list = NULL;
    CIPHER_ORDER                *head = NULL;
    CIPHER_ORDER                *tail = NULL;
    CIPHER_ORDER                *curr = NULL;
    int                         ok;
    int                         num_of_ciphers;

    if (rule_str == NULL || cipher_list == NULL || cipher_list_by_id == NULL) {
        return NULL;
    }

    /*
     * Now we have to collect the available ciphers from the compiled
     * in ciphers. We cannot get more than the number compiled in, so
     * it is used for allocation.
     */
    num_of_ciphers = method->md_num_ciphers();

    co_list = FALCONTLS_malloc(sizeof(*co_list) * num_of_ciphers);
    if (co_list == NULL) {
        return (NULL);
    }

    tls_cipher_collect_ciphers(method, num_of_ciphers, co_list,
            &head, &tail);

    /* Now arrange all ciphers by preference. */

    /*
     * Everything else being equal, prefer ephemeral ECDH over other key
     * exchange mechanisms.
     * For consistency, prefer ECDSA over RSA (though this only matters if the
     * server has both certificates, and is using the DEFAULT, or a client
     * preference).
     */
    tls_cipher_apply_rule(0, TLS_kECDHE, TLS_aECDSA, 0, 0, 0, 0, CIPHER_ADD,
                          -1, &head, &tail);
    tls_cipher_apply_rule(0, TLS_kECDHE, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head,
                          &tail);
    //tls_cipher_apply_rule(0, TLS_kECDHE, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head,
    //                      &tail);

    /* Within each strength group, we prefer GCM over CHACHA... */
    tls_cipher_apply_rule(0, 0, 0, TLS_AESGCM, 0, 0, 0, CIPHER_ADD, -1,
                          &head, &tail);
    tls_cipher_apply_rule(0, 0, 0, TLS_CHACHA20, 0, 0, 0, CIPHER_ADD, -1,
                          &head, &tail);

    /*
     * ...and generally, our preferred cipher is AES.
     * Note that AEADs will be bumped to take preference after sorting by
     * strength.
     */
    tls_cipher_apply_rule(0, 0, 0, TLS_AES ^ TLS_AESGCM, 0, 0, 0, CIPHER_ADD,
                          -1, &head, &tail);

    /* Temporarily enable everything else for sorting */
    tls_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head, &tail);

    /*
     * tls_cipher_apply_rule(0, 0, TLS_aDH, 0, 0, 0, 0, CIPHER_ORD, -1,
     * &head, &tail);
     */
    tls_cipher_apply_rule(0, TLS_kRSA, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);
    /*
     * Now sort by symmetric encryption strength.  The above ordering remains
     * in force within each class
     */
    if (!tls_cipher_strength_sort(&head, &tail)) {
        FALCONTLS_free(co_list);
        FC_LOG("strength_sort failed\n");
        return NULL;
    }

    /*
     * Partially overrule strength sort to prefer TLS 1.2 ciphers/PRFs.
     * TODO(openssl-team): is there an easier way to accomplish all this?
     */
    tls_cipher_apply_rule(0, 0, 0, 0, 0, FC_TLS1_2_VERSION, 0, CIPHER_BUMP, -1,
                          &head, &tail);

    /*
     * Irrespective of strength, enforce the following order:
     * (EC)DHE + AEAD > (EC)DHE > rest of AEAD > rest.
     * Within each group, ciphers remain sorted by strength and previous
     * preference, i.e.,
     * 1) ECDHE > DHE
     * 2) GCM > CHACHA
     * 3) AES > rest
     * 4) TLS 1.2 > legacy
     *
     * Because we now bump ciphers to the top of the list, we proceed in
     * reverse order of preference.
     */
    tls_cipher_apply_rule(0, 0, 0, 0, TLS_AEAD, 0, 0, CIPHER_BUMP, -1,
                          &head, &tail);
    tls_cipher_apply_rule(0, TLS_kDHE | TLS_kECDHE, 0, 0, 0, 0, 0,
                          CIPHER_BUMP, -1, &head, &tail);
    tls_cipher_apply_rule(0, TLS_kDHE | TLS_kECDHE, 0, 0, TLS_AEAD, 0, 0,
                          CIPHER_BUMP, -1, &head, &tail);

    /* Now disable everything (maintaining the ordering!) */
    //tls_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head, &tail);

    /*
     * If the rule_string begins with DEFAULT, apply the default rule
     * before using the (possibly available) additional rules.
     */
    ok = 1;
    rule_p = rule_str;
    if (strncmp(rule_str, "DEFAULT", 7) == 0) {
        ok = tls_cipher_process_rulestr(FC_TLS_DEFAULT_CIPHER_LIST,
                                        &head, &tail, ca_list, c);
        rule_p += 7;
        if (*rule_p == ':') {
            rule_p++;
        }
    }

    if (ok && (strlen(rule_p) > 0)) {
        ok = tls_cipher_process_rulestr(rule_p, &head, &tail, ca_list, c);
    }

    FALCONTLS_free(ca_list);      /* Not needed anymore */

    if (!ok) {                  /* Rule processing failure */
        FALCONTLS_free(co_list);
        FC_LOG("Not ok!\n");
        return (NULL);
    }

    /*
     * Allocate new "cipherstack" for the result, return with error
     * if we cannot get one.
     */
    if ((cipherstack = sk_TLS_CIPHER_new_null()) == NULL) {
        FALCONTLS_free(co_list);
        FC_LOG("New TLS_CIPHER failed!\n");
        return (NULL);
    }

    /*
     * The cipher selection for the list is done. The ciphers are added
     * to the resulting precedence to the STACK_OF(TLS_CIPHER).
     */
    for (curr = head; curr != NULL; curr = curr->next) {
        if (curr->active) {
            if (!sk_TLS_CIPHER_push(cipherstack, curr->cipher)) {
                FALCONTLS_free(co_list);
                sk_TLS_CIPHER_free(cipherstack);
                FC_LOG("push CIPHER %s failed!\n", curr->cipher->cp_name);
                return NULL;
            }
            fprintf(stderr, "<%s>\n", curr->cipher->cp_name);
        }
    }
    FALCONTLS_free(co_list);      /* Not needed any longer */

    tmp_cipher_list = sk_TLS_CIPHER_dup(cipherstack);
    if (tmp_cipher_list == NULL) {
        sk_TLS_CIPHER_free(cipherstack);
        FC_LOG("sk_TLS_CIPHER_dup failed!\n");
        return NULL;
    }
    sk_TLS_CIPHER_free(*cipher_list);
    *cipher_list = cipherstack;
    if (*cipher_list_by_id != NULL) {
        sk_TLS_CIPHER_free(*cipher_list_by_id);
    }
    *cipher_list_by_id = tmp_cipher_list;
    (void)sk_TLS_CIPHER_set_cmp_func(*cipher_list_by_id, tls_cipher_ptr_id_cmp);

    sk_TLS_CIPHER_sort(*cipher_list_by_id);
 
    return (cipherstack);
}

const TLS_CIPHER *
tls_get_cipher_by_char(TLS *s, const fc_u8 *ptr)
{
    return s->tls_method->md_get_cipher_by_char(ptr);
}

