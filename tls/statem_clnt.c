#include <string.h>

#include <falcontls/types.h>
#include <fc_log.h>

#include "statem.h"
#include "alert.h"
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

static int
tls_set_client_hello_version(TLS *s)
{
    return 0;
}

static int
tls_construct_client_hello(TLS *s)
{
    //fc_u8       *buf = NULL;
    fc_u8       *p = NULL;
    fc_u8       *d = NULL;
    fc_ulong    l = 0;
    int         protverr;
#if 0
    int i;
    int al = 0;
    SSL_SESSION *sess = s->session;
#endif

    //buf = (fc_u8 *)s->tls_init_buf->bm_data;

    /* Work out what SSL/TLS/DTLS version to use */
    protverr = tls_set_client_hello_version(s);
    if (protverr != 0) {
        goto err;
    }

#if 0
    if ((sess == NULL) || !ssl_version_supported(s, sess->ssl_version) ||
        /*
         * In the case of EAP-FAST, we can have a pre-shared
         * "ticket" without a session ID.
         */
        (!sess->session_id_length && !sess->tlsext_tick) ||
        (sess->not_resumable)) {
        if (!ssl_get_new_session(s, 0))
            goto err;
    }
    /* else use the pre-loaded session */

#endif
    p = s->tls1.st_client_random;

    if (tls_fill_hello_random(s, 0, p, sizeof(s->tls1.st_client_random)) <= 0) {
        goto err;
    }

    /* Do the message type and length last */
    d = p = tls_handshake_start(s);

    *(p++) = s->tls_version >> 8;
    *(p++) = s->tls_version & 0xff;

    /* Random stuff */
    memcpy(p, s->tls1.st_client_random, TLS_RANDOM_SIZE);
    p += TLS_RANDOM_SIZE;

#if 0
    /* Session ID */
    if (s->new_session)
        i = 0;
    else
        i = s->session->session_id_length;
    *(p++) = i;
    if (i != 0) {
        if (i > (int)sizeof(s->session->session_id)) {
            SSLerr(SSL_F_TLS_CONSTRUCT_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(p, s->session->session_id, i);
        p += i;
    }

    /* Ciphers supported */
    i = ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), &(p[2]));
    if (i == 0) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CLIENT_HELLO, SSL_R_NO_CIPHERS_AVAILABLE);
        goto err;
    }
#ifdef OPENSSL_MAX_TLS1_2_CIPHER_LENGTH
    /*
     * Some servers hang if client hello > 256 bytes as hack workaround
     * chop number of supported ciphers to keep it well below this if we
     * use TLS v1.2
     */
    if (TLS1_get_version(s) >= TLS1_2_VERSION
        && i > OPENSSL_MAX_TLS1_2_CIPHER_LENGTH)
        i = OPENSSL_MAX_TLS1_2_CIPHER_LENGTH & ~1;
#endif
    s2n(i, p);
    p += i;

    *(p++) = 1;
    *(p++) = 0;                 /* Add the NULL method */

    /* TLS extensions */
    if (ssl_prepare_clienthello_tlsext(s) <= 0) {
        SSLerr(SSL_F_TLS_CONSTRUCT_CLIENT_HELLO, SSL_R_CLIENTHELLO_TLSEXT);
        goto err;
    }
    if ((p =
         ssl_add_clienthello_tlsext(s, p, buf + SSL3_RT_MAX_PLAIN_LENGTH,
                                    &al)) == NULL) {
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        SSLerr(SSL_F_TLS_CONSTRUCT_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#endif

    l = p - d;
    if (!tls_set_handshake_header(s, TLS_HANDSHAKE_TYPE_CLIENT_HELLO, l)) {
        tls_send_alert(s, TLS_AL_FATAL, TLS_AD_HANDSHAKE_FAILURE);
        goto err;
    }

    return 1;
 err:
    //ossl_statem_set_error(s);
    return 0;
}


int
tls_statem_client_construct_message(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;

    switch (st->sm_hand_state) {
        case TLS_ST_CW_CLNT_HELLO:
            return tls_construct_client_hello(s);
 
        default:
            break;
    }

    return 0;
}
