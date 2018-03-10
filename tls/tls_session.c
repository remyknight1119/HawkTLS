
#include <falcontls/types.h>
#include <falcontls/tls.h>
#include <falcontls/crypto.h>
#include <fc_log.h>

#include "tls_locl.h"

TLS_SESSION *
TLS_SESSION_new(void)
{
    TLS_SESSION     *ss = NULL;

    ss = FALCONTLS_calloc(sizeof(*ss));
    if (ss == NULL) {
        FC_LOG("Alloc session failed\n");
        return NULL;
    }

    return ss;
}

void
TLS_SESSION_free(TLS_SESSION *ss)
{
    if (ss == NULL) {
        return;
    }

    FALCONTLS_free(ss);
}

int
tls_get_new_session(TLS *s, int session)
{
    TLS_SESSION     *ss = NULL;

    if ((ss = TLS_SESSION_new()) == NULL) {
        return 0;
    }

    TLS_SESSION_free(s->tls_session);
    s->tls_session = NULL;

    if (session) {
        ss->se_session_id_length = FC_TLS_SESSION_ID_LENGTH;
    } else {
        ss->se_session_id_length = 0;
    }

    s->tls_session = ss;

    return 1;
}
