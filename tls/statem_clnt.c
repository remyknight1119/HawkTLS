
#include <falcontls/types.h>
#include <fc_log.h>

#include "statem.h"
#include "packet.h"
#include "record_locl.h"
#include "tls_locl.h"
#include "statem_locl.h"

int
tls_statem_client_read_transition(TLS *s, int mt)
{
    return 1;
}

MSG_PROCESS_RETURN
tls_statem_client_process_message(TLS *s, PACKET *pkt)
{
    return MSG_PROCESS_ERROR;
}

WORK_STATE
tls_statem_client_post_process_message(TLS *s, WORK_STATE wst)
{
    return WORK_ERROR;
}

fc_ulong
tls_statem_client_max_message_size(TLS *s)
{
    return 0;
}

WRITE_TRAN
tls_statem_client_write_transition(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;

    switch (st->sm_hand_state) {
        case TLS_ST_OK:
            /* Renegotiation - fall through */
        case TLS_ST_BEFORE:
            st->sm_hand_state = TLS_ST_CW_CLNT_HELLO;
            return WRITE_TRAN_CONTINUE;

        case TLS_ST_CW_CLNT_HELLO:
            /*
             * No transition at the end of writing because we don't know what
             * we will be sent
             */
            return WRITE_TRAN_FINISHED;
        default:
            return WRITE_TRAN_ERROR;
    }
}

WORK_STATE
tls_statem_client_pre_work(TLS *s, WORK_STATE wst)
{
    return WORK_FINISHED_CONTINUE;
}

WORK_STATE
tls_statem_client_post_work(TLS *s, WORK_STATE wst)
{
//    TLS_STATEM  *st = &s->tls_statem;

    s->tls_init_num = 0;

    return WORK_FINISHED_CONTINUE;
}

int
tls_statem_client_construct_message(TLS *s)
{
    return 1;
}
