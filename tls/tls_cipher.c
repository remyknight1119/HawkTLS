#include <string.h>

#include <falcontls/tls.h>
#include <falcontls/crypto.h>
#include <falcontls/x509.h>
#include <fc_log.h>

#include "tls1.h"
#include "tls_locl.h"


FC_STACK_OF(TLS_CIPHER) *
tls_create_cipher_list(const TLS_METHOD *method, FC_STACK_OF(TLS_CIPHER) **pref,
                        FC_STACK_OF(TLS_CIPHER) **sorted, const char *rule_str,
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
    int                         num_of_alias_max;
    int                         num_of_group_aliases;

    if (rule_str == NULL || cipher_list == NULL || cipher_list_by_id == NULL) {
        return NULL;
    }

    if (!check_suiteb_cipher_list(method, c, &rule_str)) {
        return NULL;
    }

    /*
     * Now we have to collect the available ciphers from the compiled
     * in ciphers. We cannot get more than the number compiled in, so
     * it is used for allocation.
     */
    num_of_ciphers = method->num_ciphers();

    co_list = FALCONTLS_malloc(sizeof(*co_list) * num_of_ciphers);
    if (co_list == NULL) {
        return (NULL);
    }

    ssl_cipher_collect_ciphers(ssl_method, num_of_ciphers,
                               disabled_mkey, disabled_auth, disabled_enc,
                               disabled_mac, co_list, &head, &tail);

    /* Now arrange all ciphers by preference. */

    /*
     * Everything else being equal, prefer ephemeral ECDH over other key
     * exchange mechanisms.
     * For consistency, prefer ECDSA over RSA (though this only matters if the
     * server has both certificates, and is using the DEFAULT, or a client
     * preference).
     */
    ssl_cipher_apply_rule(0, TLS_kECDHE, TLS_aECDSA, 0, 0, 0, 0, CIPHER_ADD,
                          -1, &head, &tail);
    ssl_cipher_apply_rule(0, TLS_kECDHE, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head,
                          &tail);
    ssl_cipher_apply_rule(0, TLS_kECDHE, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head,
                          &tail);

    /* Within each strength group, we prefer GCM over CHACHA... */
    ssl_cipher_apply_rule(0, 0, 0, TLS_AESGCM, 0, 0, 0, CIPHER_ADD, -1,
                          &head, &tail);
    ssl_cipher_apply_rule(0, 0, 0, TLS_CHACHA20, 0, 0, 0, CIPHER_ADD, -1,
                          &head, &tail);

    /*
     * ...and generally, our preferred cipher is AES.
     * Note that AEADs will be bumped to take preference after sorting by
     * strength.
     */
    ssl_cipher_apply_rule(0, 0, 0, TLS_AES ^ TLS_AESGCM, 0, 0, 0, CIPHER_ADD,
                          -1, &head, &tail);

    /* Temporarily enable everything else for sorting */
    ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head, &tail);

    /*
     * ssl_cipher_apply_rule(0, 0, TLS_aDH, 0, 0, 0, 0, CIPHER_ORD, -1,
     * &head, &tail);
     */
    ssl_cipher_apply_rule(0, TLS_kRSA, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);
    /*
     * Now sort by symmetric encryption strength.  The above ordering remains
     * in force within each class
     */
    if (!ssl_cipher_strength_sort(&head, &tail)) {
        FALCONTLS_free(co_list);
        return NULL;
    }

    /*
     * Partially overrule strength sort to prefer TLS 1.2 ciphers/PRFs.
     * TODO(openssl-team): is there an easier way to accomplish all this?
     */
    ssl_cipher_apply_rule(0, 0, 0, 0, 0, TLS1_2_VERSION, 0, CIPHER_BUMP, -1,
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
    ssl_cipher_apply_rule(0, 0, 0, 0, TLS_AEAD, 0, 0, CIPHER_BUMP, -1,
                          &head, &tail);
    ssl_cipher_apply_rule(0, TLS_kDHE | TLS_kECDHE, 0, 0, 0, 0, 0,
                          CIPHER_BUMP, -1, &head, &tail);
    ssl_cipher_apply_rule(0, TLS_kDHE | TLS_kECDHE, 0, 0, TLS_AEAD, 0, 0,
                          CIPHER_BUMP, -1, &head, &tail);

    /* Now disable everything (maintaining the ordering!) */
    ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head, &tail);

    /*
     * We also need cipher aliases for selecting based on the rule_str.
     * There might be two types of entries in the rule_str: 1) names
     * of ciphers themselves 2) aliases for groups of ciphers.
     * For 1) we need the available ciphers and for 2) the cipher
     * groups of cipher_aliases added together in one list (otherwise
     * we would be happy with just the cipher_aliases table).
     */
    num_of_group_aliases = OTLS_NELEM(cipher_aliases);
    num_of_alias_max = num_of_ciphers + num_of_group_aliases + 1;
    ca_list = FALCONTLS_malloc(sizeof(*ca_list) * num_of_alias_max);
    if (ca_list == NULL) {
        FALCONTLS_free(co_list);
        SSLerr(TLS_F_TLS_CREATE_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
        return (NULL);          /* Failure */
    }
    ssl_cipher_collect_aliases(ca_list, num_of_group_aliases,
                               disabled_mkey, disabled_auth, disabled_enc,
                               disabled_mac, head);

    /*
     * If the rule_string begins with DEFAULT, apply the default rule
     * before using the (possibly available) additional rules.
     */
    ok = 1;
    rule_p = rule_str;
    if (strncmp(rule_str, "DEFAULT", 7) == 0) {
        ok = ssl_cipher_process_rulestr(TLS_DEFAULT_CIPHER_LIST,
                                        &head, &tail, ca_list, c);
        rule_p += 7;
        if (*rule_p == ':')
            rule_p++;
    }

    if (ok && (strlen(rule_p) > 0))
        ok = ssl_cipher_process_rulestr(rule_p, &head, &tail, ca_list, c);

    FALCONTLS_free(ca_list);      /* Not needed anymore */

    if (!ok) {                  /* Rule processing failure */
        FALCONTLS_free(co_list);
        return (NULL);
    }

    /*
     * Allocate new "cipherstack" for the result, return with error
     * if we cannot get one.
     */
    if ((cipherstack = sk_TLS_CIPHER_new_null()) == NULL) {
        FALCONTLS_free(co_list);
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
                return NULL;
            }
            fprintf(stderr, "<%s>\n", curr->cipher->name);
        }
    }
    FALCONTLS_free(co_list);      /* Not needed any longer */

    tmp_cipher_list = sk_TLS_CIPHER_dup(cipherstack);
    if (tmp_cipher_list == NULL) {
        sk_TLS_CIPHER_free(cipherstack);
        return NULL;
    }
    sk_TLS_CIPHER_free(*cipher_list);
    *cipher_list = cipherstack;
    if (*cipher_list_by_id != NULL)
        sk_TLS_CIPHER_free(*cipher_list_by_id);
    *cipher_list_by_id = tmp_cipher_list;
    (void)sk_TLS_CIPHER_set_cmp_func(*cipher_list_by_id, ssl_cipher_ptr_id_cmp);

    sk_TLS_CIPHER_sort(*cipher_list_by_id);
 
    return (cipherstack);
}
