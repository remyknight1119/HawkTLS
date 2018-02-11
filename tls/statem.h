#ifndef __FC_STATEM_H__
#define __FC_STATEM_H__

#include <stdbool.h>

#include <falcontls/tls.h>

typedef enum {
    TLS_ST_BEFORE,
    TLS_ST_OK,
} TLS_HANDSHAKE_STATE;

typedef enum {
    /* No handshake in progress */
    TLS_MSG_FLOW_UNINITED,
    /* A permanent error with this connection */
    TLS_MSG_FLOW_ERROR,
    /* We are about to renegotiate */
    TLS_MSG_FLOW_RENEGOTIATE,
    /* We are reading messages */
    TLS_MSG_FLOW_READING,
    /* We are writing messages */
    TLS_MSG_FLOW_WRITING,
    /* Handshake has finished */
    TLS_MSG_FLOW_FINISHED
} TLS_MSG_FLOW_STATE;


typedef struct tls_statem_t {
    TLS_MSG_FLOW_STATE  sm_state;
    TLS_HANDSHAKE_STATE sm_hand_state;
    bool                sm_init;
    int                 sm_in_handshake;
} TLS_STATEM;

int tls_statem_accept(TLS *s);
int tls_statem_connect(TLS *s);
int TLS_init(TLS *s);

#endif
