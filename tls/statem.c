
#include <falcontls/types.h>
#include <falcontls/buffer.h>

#include "statem.h"
#include "record_locl.h"
#include "tls_locl.h"

static int
tls_state_machine(TLS *s, int server)
{
    TLS_STATEM  *st = &s->tls_statem;
    FC_BUF_MEM  *buf = NULL;
    int         ret = -1;

    st->sm_in_handshake++;
    if (st->sm_state == TLS_MSG_FLOW_UNINITED || 
            st->sm_state == TLS_MSG_FLOW_RENEGOTIATE) {
        if (st->sm_state == TLS_MSG_FLOW_UNINITED) {
            st->sm_hand_state = TLS_ST_BEFORE;
        }
        s->tls_server = server;
        if (s->tls_init_buf == NULL) {
            if ((buf = FC_BUF_MEM_new()) == NULL) {
                goto end;
            }
            if (!FC_BUF_MEM_grow(buf, FC_TLS_RT_MAX_PLAIN_LENGTH)) {
                goto end;
            }
            s->tls_init_buf = buf;
            buf = NULL;
        }

        if (!tls_setup_buffers(s)) {
            goto end;
        }
    }

end:
    st->sm_in_handshake--;
    FC_BUF_MEM_free(buf);

    return ret;
}

int
tls_statem_accept(TLS *s)
{
    return tls_state_machine(s, 1);
}

int
tls_statem_connect(TLS *s)
{
    return tls_state_machine(s, 0);
}

int
TLS_init(TLS *s)
{
    return s->tls_statem.sm_init;
}


