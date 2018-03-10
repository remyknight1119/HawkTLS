
#include <falcontls/tls.h>
#include <falcontls/crypto.h>
#include <falcontls/x509.h>
#include <fc_log.h>

#include "tls_locl.h"


FC_STACK_OF(TLS_CIPHER) *
tls_create_cipher_list(const TLS_METHOD *meth, FC_STACK_OF(TLS_CIPHER) **pref,
                        FC_STACK_OF(TLS_CIPHER) **sorted, const char *rule_str,
                        CERT *c)
{
    FC_STACK_OF(TLS_CIPHER)     *cipherstack = NULL;

    return (cipherstack);
}
