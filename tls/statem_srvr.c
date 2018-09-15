
#include <falcontls/types.h>

#include "statem.h"
#include "packet.h"
#include "record_locl.h"
#include "tls_locl.h"
#include "statem_locl.h"

int
tls_statem_server_read_transition(TLS *s, int mt)
{
    return 1;
}

MSG_PROCESS_RETURN
tls_statem_server_process_message(TLS *s, PACKET *pkt)
{
    return MSG_PROCESS_ERROR;
}

WORK_STATE
tls_statem_server_post_process_message(TLS *s, WORK_STATE wst)
{
    return WORK_ERROR;
}

fc_ulong
tls_statem_server_max_message_size(TLS *s)
{
    return 0;
}

WRITE_TRAN
tls_statem_server_write_transition(TLS *s)
{
    return WRITE_TRAN_ERROR;
}

WORK_STATE
tls_statem_server_pre_work(TLS *s, WORK_STATE wst)
{
    return WORK_FINISHED_CONTINUE;
}

WORK_STATE
tls_statem_server_post_work(TLS *s, WORK_STATE wst)
{
    return WORK_FINISHED_CONTINUE;
}

int
tls_statem_server_construct_message(TLS *s, WPACKET *pkt,
                confunc_f *confunc, int *mt)
{
    return 0;
}
