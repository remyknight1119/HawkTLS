#ifndef __FC_STATEM_H__
#define __FC_STATEM_H__

#include <stdbool.h>

#include <falcontls/tls.h>

typedef enum {
    TLS_ST_BEFORE,
    TLS_ST_OK,
    DTLS_ST_CR_HELLO_VERIFY_REQUEST,
    TLS_ST_CR_SRVR_HELLO,
    TLS_ST_CR_CERT,
    TLS_ST_CR_CERT_STATUS,
    TLS_ST_CR_KEY_EXCH,
    TLS_ST_CR_CERT_REQ,
    TLS_ST_CR_SRVR_DONE,
    TLS_ST_CR_SESSION_TICKET,
    TLS_ST_CR_CHANGE,
    TLS_ST_CR_FINISHED,
    TLS_ST_CW_CLNT_HELLO,
    TLS_ST_CW_CERT,
    TLS_ST_CW_KEY_EXCH,
    TLS_ST_CW_CERT_VRFY,
    TLS_ST_CW_CHANGE,
    TLS_ST_CW_NEXT_PROTO,
    TLS_ST_CW_FINISHED,
    TLS_ST_SW_HELLO_REQ,
    TLS_ST_SR_CLNT_HELLO,
    DTLS_ST_SW_HELLO_VERIFY_REQUEST,
    TLS_ST_SW_SRVR_HELLO,
    TLS_ST_SW_CERT,
    TLS_ST_SW_KEY_EXCH,
    TLS_ST_SW_CERT_REQ,
    TLS_ST_SW_SRVR_DONE,
    TLS_ST_SR_CERT,
    TLS_ST_SR_KEY_EXCH,
    TLS_ST_SR_CERT_VRFY,
    TLS_ST_SR_NEXT_PROTO,
    TLS_ST_SR_CHANGE,
    TLS_ST_SR_FINISHED,
    TLS_ST_SW_SESSION_TICKET,
    TLS_ST_SW_CERT_STATUS,
    TLS_ST_SW_CHANGE,
    TLS_ST_SW_FINISHED
} TLS_HANDSHAKE_STATE;

typedef enum {
    /* No handshake in progress */
    MSG_FLOW_UNINITED,
    /* A permanent error with this connection */
    MSG_FLOW_ERROR,
    /* We are about to renegotiate */
    MSG_FLOW_RENEGOTIATE,
    /* We are reading messages */
    MSG_FLOW_READING,
    /* We are writing messages */
    MSG_FLOW_WRITING,
    /* Handshake has finished */
    MSG_FLOW_FINISHED
} MSG_FLOW_STATE;

/* Read states */
typedef enum {
    READ_STATE_HEADER,
    READ_STATE_BODY,
    READ_STATE_POST_PROCESS
} READ_STATE;

/* Write states */
typedef enum {
    WRITE_STATE_TRANSITION,
    WRITE_STATE_PRE_WORK,
    WRITE_STATE_SEND,
    WRITE_STATE_POST_WORK
} WRITE_STATE;

typedef struct tls_statem_t {
    MSG_FLOW_STATE      sm_state;
    WRITE_STATE         sm_write_state;
    READ_STATE          sm_read_state;
    TLS_HANDSHAKE_STATE sm_hand_state;
    bool                sm_init;
    int                 sm_in_handshake;
} TLS_STATEM;

int tls_statem_accept(TLS *s);
int tls_statem_connect(TLS *s);
int TLS_init(TLS *s);

#endif
