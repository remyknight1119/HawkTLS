#ifndef __FC_STATEM_LOCL_H__
#define __FC_STATEM_LOCL_H__

#include "statem.h"
#include "packet.h"

typedef enum {
    /* Something bad happened */
    MSG_PROCESS_ERROR,
    /* We've finished reading - swap to writing */
    MSG_PROCESS_FINISHED_READING,
    /*
     * We've completed the main processing of this message but there is some
     * post processing to be done.
     */
    MSG_PROCESS_CONTINUE_PROCESSING,
    /* We've finished this message - read the next message */
    MSG_PROCESS_CONTINUE_READING
} MSG_PROCESS_RETURN;

int tls_statem_server_read_transition(TLS *s, int mt);
MSG_PROCESS_RETURN tls_statem_server_process_message(TLS *s, PACKET *pkt);
WORK_STATE tls_statem_server_post_process_message(TLS *s, WORK_STATE wst);
fc_ulong tls_statem_server_max_message_size(TLS *s);
WRITE_TRAN tls_statem_server_write_transition(TLS *s);
WORK_STATE tls_statem_server_pre_work(TLS *s, WORK_STATE wst);
WORK_STATE tls_statem_server_post_work(TLS *s, WORK_STATE wst);
int tls_statem_server_construct_message(TLS *s);

int tls_statem_client_read_transition(TLS *s, int mt);
MSG_PROCESS_RETURN tls_statem_client_process_message(TLS *s, PACKET *pkt);
WORK_STATE tls_statem_client_post_process_message(TLS *s, WORK_STATE wst);
fc_ulong tls_statem_client_max_message_size(TLS *s);
WRITE_TRAN tls_statem_client_write_transition(TLS *s);
WORK_STATE tls_statem_client_pre_work(TLS *s, WORK_STATE wst);
WORK_STATE tls_statem_client_post_work(TLS *s, WORK_STATE wst);
int tls_statem_client_construct_message(TLS *s);

#endif
