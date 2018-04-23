#include <string.h>

#include <falcontls/types.h>
#include <falcontls/safestack.h>
#include <fc_assert.h>
#include <fc_log.h>

#include "statem.h"
#include "alert.h"
#include "packet.h"
#include "record_locl.h"
#include "tls_locl.h"
#include "tls1.h"
#include "statem_locl.h"

typedef MSG_PROCESS_RETURN (*TLS_CLNT_PROC_F)(TLS *, PACKET *);

typedef struct tls_client_process_t {
    TLS_HANDSHAKE_STATE     pc_hand_state;
    TLS_CLNT_PROC_F         pc_proc;
} CLIENT_PROCESS;

static MSG_PROCESS_RETURN tls_process_server_hello(TLS *s, PACKET *pkt);

static const CLIENT_PROCESS tls_statem_client_process[] = {
    {
        .pc_hand_state = TLS_ST_CR_SRVR_HELLO,
        .pc_proc = tls_process_server_hello,
    },
};

#define TLS_CLIENT_PROCESS_NUM  FC_ARRAY_SIZE(tls_statem_client_process)

static TLS_CLNT_PROC_F tls_statem_client_proc_func[TLS_ST_SW_MAX];

void
tls_statem_client_init(void)
{
    TLS_HANDSHAKE_STATE     state = 0;
    int                     i = 0;

    for (i = 0; i < TLS_CLIENT_PROCESS_NUM; i++) {
        state = tls_statem_client_process[i].pc_hand_state;
        if (state >= TLS_ST_SW_MAX) {
            FC_LOG("State(%d) init failed\n", state);
            continue;
        }
        tls_statem_client_proc_func[state] =
            tls_statem_client_process[i].pc_proc;
    }
}

int
tls_statem_client_read_transition(TLS *s, int mt)
{
    TLS_STATEM  *st = &s->tls_statem;
    //int ske_expected;

    switch (st->sm_hand_state) {
    case TLS_ST_CW_CLNT_HELLO:
        if (mt == TLS1_MT_SERVER_HELLO) {
            st->sm_hand_state = TLS_ST_CR_SRVR_HELLO;
            return 1;
        }

        break;

    case TLS_ST_CR_SRVR_HELLO:
#if 0
        if (s->hit) {
            if (s->tlsext_ticket_expected) {
                if (mt == TLS1_MT_NEWSESSION_TICKET) {
                    st->sm_hand_state = TLS_ST_CR_SESSION_TICKET;
                    return 1;
                }
            } else if (mt == TLS1_MT_CHANGE_CIPHER_SPEC) {
                st->sm_hand_state = TLS_ST_CR_CHANGE;
                return 1;
            }
        } else {
            if (TLS_IS_DTLS(s) && mt == DTLS1_MT_HELLO_VERIFY_REQUEST) {
                st->sm_hand_state = DTLS_ST_CR_HELLO_VERIFY_REQUEST;
                return 1;
            } else if (s->version >= TLS1_VERSION
                       && s->tls_session_secret_cb != NULL
                       && s->session->tlsext_tick != NULL
                       && mt == TLS1_MT_CHANGE_CIPHER_SPEC) {
                /*
                 * Normally, we can tell if the server is resuming the session
                 * from the session ID. EAP-FAST (RFC 4851), however, relies on
                 * the next server message after the ServerHello to determine if
                 * the server is resuming.
                 */
                s->hit = 1;
                st->sm_hand_state = TLS_ST_CR_CHANGE;
                return 1;
            } else if (!(s->s3->tmp.new_cipher->algorithm_auth
                         & (TLS_aNULL | TLS_aSRP | TLS_aPSK))) {
                if (mt == TLS1_MT_CERTIFICATE) {
                    st->sm_hand_state = TLS_ST_CR_CERT;
                    return 1;
                }
            } else {
                ske_expected = key_exchange_expected(s);
                /* SKE is optional for some PSK ciphersuites */
                if (ske_expected
                    || ((s->s3->tmp.new_cipher->algorithm_mkey & TLS_PSK)
                        && mt == TLS1_MT_SERVER_KEY_EXCHANGE)) {
                    if (mt == TLS1_MT_SERVER_KEY_EXCHANGE) {
                        st->sm_hand_state = TLS_ST_CR_KEY_EXCH;
                        return 1;
                    }
                } else if (mt == TLS1_MT_CERTIFICATE_REQUEST
                           && cert_req_allowed(s)) {
                    st->sm_hand_state = TLS_ST_CR_CERT_REQ;
                    return 1;
                } else if (mt == TLS1_MT_SERVER_DONE) {
                    st->sm_hand_state = TLS_ST_CR_SRVR_DONE;
                    return 1;
                }
            }
        }
#endif
        break;

    case TLS_ST_CR_CERT:
#if 0
        /*
         * The CertificateStatus message is optional even if
         * |tlsext_status_expected| is set
         */
        if (s->tlsext_status_expected && mt == TLS1_MT_CERTIFICATE_STATUS) {
            st->sm_hand_state = TLS_ST_CR_CERT_STATUS;
            return 1;
        }
#endif
        /* Fall through */

    case TLS_ST_CR_CERT_STATUS:
#if 0
        ske_expected = key_exchange_expected(s);
        /* SKE is optional for some PSK ciphersuites */
        if (ske_expected || ((s->s3->tmp.new_cipher->algorithm_mkey & TLS_PSK)
                             && mt == TLS1_MT_SERVER_KEY_EXCHANGE)) {
            if (mt == TLS1_MT_SERVER_KEY_EXCHANGE) {
                st->sm_hand_state = TLS_ST_CR_KEY_EXCH;
                return 1;
            }
            goto err;
        }
#endif
        /* Fall through */

    case TLS_ST_CR_KEY_EXCH:
        if (mt == TLS1_MT_CERTIFICATE_REQUEST) {
#if 0
            if (cert_req_allowed(s)) {
                st->sm_hand_state = TLS_ST_CR_CERT_REQ;
                return 1;
            }
#endif
            goto err;
        }
        /* Fall through */

    case TLS_ST_CR_CERT_REQ:
        if (mt == TLS1_MT_SERVER_DONE) {
            st->sm_hand_state = TLS_ST_CR_SRVR_DONE;
            return 1;
        }
        break;

    case TLS_ST_CW_FINISHED:
#if 0
        if (s->tlsext_ticket_expected) {
            if (mt == TLS1_MT_NEWSESSION_TICKET) {
                st->sm_hand_state = TLS_ST_CR_SESSION_TICKET;
                return 1;
            }
        } else if (mt == TLS1_MT_CHANGE_CIPHER_SPEC) {
            st->sm_hand_state = TLS_ST_CR_CHANGE;
            return 1;
        }
#endif
        break;

    case TLS_ST_CR_SESSION_TICKET:
        if (mt == TLS1_MT_CHANGE_CIPHER_SPEC) {
            st->sm_hand_state = TLS_ST_CR_CHANGE;
            return 1;
        }
        break;

    case TLS_ST_CR_CHANGE:
        if (mt == TLS1_MT_FINISHED) {
            st->sm_hand_state = TLS_ST_CR_FINISHED;
            return 1;
        }
        break;

    default:
        break;
    }

 err:
    /* No valid transition found */
    tls_send_alert(s, TLS_AL_FATAL, TLS_AD_UNEXPECTED_MESSAGE);
    return 0;
}

MSG_PROCESS_RETURN
tls_statem_client_process_message(TLS *s, PACKET *pkt)
{
    TLS_STATEM          *st = &s->tls_statem;
    TLS_CLNT_PROC_F     proc = NULL;

    fc_assert(st->sm_hand_state < TLS_ST_SW_MAX);
    proc = tls_statem_client_proc_func[st->sm_hand_state];
    if (proc == NULL) {
        FC_LOG("Can't process state %d\n", st->sm_hand_state);
        return MSG_PROCESS_ERROR;
    }

    return proc(s, pkt);
}

WORK_STATE
tls_statem_client_post_process_message(TLS *s, WORK_STATE wst)
{
    FC_LOG("in\n");
    return WORK_ERROR;
}

fc_ulong
tls_statem_client_max_message_size(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;

    switch (st->sm_hand_state) {
    case TLS_ST_CR_SRVR_HELLO:
        return SERVER_HELLO_MAX_LENGTH;

    case DTLS_ST_CR_HELLO_VERIFY_REQUEST:
        return HELLO_VERIFY_REQUEST_MAX_LENGTH;

    case TLS_ST_CR_CERT:
        return s->tls_max_cert_list;

    case TLS_ST_CR_CERT_STATUS:
        return TLS1_RT_MAX_PLAIN_LENGTH;

    case TLS_ST_CR_KEY_EXCH:
        return SERVER_KEY_EXCH_MAX_LENGTH;

    case TLS_ST_CR_CERT_REQ:
        /*
         * Set to s->max_cert_list for compatibility with previous releases. In
         * practice these messages can get quite long if servers are configured
         * to provide a long list of acceptable CAs
         */
        return s->tls_max_cert_list;

    case TLS_ST_CR_SRVR_DONE:
        return SERVER_HELLO_DONE_MAX_LENGTH;

    case TLS_ST_CR_CHANGE:
        return CCS_MAX_LENGTH;

    case TLS_ST_CR_SESSION_TICKET:
        return TLS1_RT_MAX_PLAIN_LENGTH;

    case TLS_ST_CR_FINISHED:
        return FINISHED_MAX_LENGTH;

    default:
        /* Shouldn't happen */
        break;
    }

    FC_LOG("State(%d) error!\n", st->sm_hand_state);
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

static MSG_PROCESS_RETURN
tls_process_server_hello(TLS *s, PACKET *pkt)
{
    FC_STACK_OF(TLS_CIPHER) *sk = NULL;
    const TLS_CIPHER        *c = NULL;
    const fc_u8             *cipherchars = NULL;
    TLS_SESSION             *session;
    PACKET                  session_id;
    size_t                  session_id_len = 0;
    fc_u32                  sversion = 0;
    fc_u32                  compression = 0;
    int                     i = 0;
    int                     al = TLS_AD_INTERNAL_ERROR;
    int                     protverr = 0;

    if (!PACKET_get_net_2(pkt, &sversion)) {
        al = TLS_AD_DECODE_ERROR;
        goto f_err;
    }

    protverr = tls_choose_client_version(s, sversion);
    if (protverr != 0) {
        al = TLS_AD_PROTOCOL_VERSION;
        goto f_err;
    }

    /* load the server hello data */
    /* load the server random */
    if (!PACKET_copy_bytes(pkt, s->tls1.st_server_random, TLS_RANDOM_SIZE)) {
        al = TLS_AD_DECODE_ERROR;
        goto f_err;
    }

    s->tls_hit = 0;

    /* Get the session-id. */
    if (!PACKET_get_length_prefixed_1(pkt, &session_id)) {
        al = TLS_AD_DECODE_ERROR;
        goto f_err;
    }
    session = s->tls_session;
    session_id_len = PACKET_remaining(&session_id);
    if (session_id_len > sizeof(session->se_session_id)
        || session_id_len > TLS_SESSION_ID_SIZE) {
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }

    if (!PACKET_get_bytes(pkt, &cipherchars, TLS_CIPHER_LEN)) {
        al = TLS_AD_DECODE_ERROR;
        goto f_err;
    }

    /*
     * Check if we can resume the session based on external pre-shared secret.
     * EAP-FAST (RFC 4851) supports two types of session resumption.
     * Resumption based on server-side state works with session IDs.
     * Resumption based on pre-shared Protected Access Credentials (PACs)
     * works by overriding the SessionTicket extension at the application
     * layer, and does not send a session ID. (We do not know whether EAP-FAST
     * servers would honour the session ID.) Therefore, the session ID alone
     * is not a reliable indicator of session resumption, so we first check if
     * we can resume, and later peek at the next handshake message to see if the
     * server wants to resume.
     */
#if 0
    if (s->tls_session_secret_cb && session->tlsext_tick) {
        const TLS_CIPHER    *pref_cipher = NULL;
        session->master_key_length = sizeof(session->se_master_key);
        if (s->tls_session_secret_cb(s, s->session->master_key,
                                     &s->session->master_key_length,
                                     NULL, &pref_cipher,
                                     s->tls_session_secret_cb_arg)) {
            session->cipher = pref_cipher ?
                pref_cipher : ssl_get_cipher_by_char(s, cipherchars);
        } else {
            al = TLS_AD_INTERNAL_ERROR;
            goto f_err;
        }
    }
#endif

    if (session_id_len != 0 && session_id_len == session->se_session_id_length
        && memcmp(PACKET_data(&session_id), session->se_session_id,
                  session_id_len) == 0) {
        if (s->tls_sid_ctx_length != session->se_sid_ctx_length
            || memcmp(session->se_sid_ctx, s->tls_sid_ctx,
                s->tls_sid_ctx_length)) {
            /* actually a client application bug */
            al = TLS_AD_ILLEGAL_PARAMETER;
            goto f_err;
        }
        s->tls_hit = 1;
    } else {
        /*
         * If we were trying for session-id reuse but the server
         * didn't echo the ID, make a new TLS_SESSION.
         * In the case of EAP-FAST and PAC, we do not send a session ID,
         * so the PAC-based session secret is always preserved. It'll be
         * overwritten if the server refuses resumption.
         */
        if (session->se_session_id_length > 0) {
            if (!tls_get_new_session(s, 0)) {
                goto f_err;
            }
        }

        session->se_session_id_length = session_id_len;
        /* session_id_len could be 0 */
        if (session_id_len > 0)
            memcpy(session->se_session_id, PACKET_data(&session_id),
                   session_id_len);
    }

    c = tls_get_cipher_by_char(s, cipherchars);
    if (c == NULL) {
        /* unknown cipher */
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }

    if (tls_cipher_disabled(s, c, 0/*SSL_SECOP_CIPHER_CHECK*/, 1)) {
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }
    sk = tls_get_ciphers_by_id(s);
    i = sk_TLS_CIPHER_find(sk, c);
    if (i < 0) {
        /* we did not say we would use this cipher */
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }

    /*
     * Depending on the session caching (internal/external), the cipher
     * and/or cipher_id values may not be set. Make sure that cipher_id is
     * set and use it for comparison.
     */
    if (session->se_cipher) {
        session->se_cipher_id = session->se_cipher->cp_id;
    }
    if (s->tls_hit && (session->se_cipher_id != c->cp_id)) {
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }
    s->tls_tmp.tm_new_cipher = c;
    /* lets get the compression algorithm */
    /* COMPRESSION */
    if (!PACKET_get_1(pkt, &compression)) {
        al = TLS_AD_DECODE_ERROR;
        goto f_err;
    }

    if (compression != 0) {
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }
    /* TLS extensions */
    if (!tls_parse_serverhello_tlsext(s, pkt)) {
        goto err;
    }

    if (PACKET_remaining(pkt) != 0) {
        /* wrong packet length */
        al = TLS_AD_DECODE_ERROR;
        goto f_err;
    }

    return MSG_PROCESS_CONTINUE_READING;
f_err:
    tls_send_alert(s, TLS_AL_FATAL, al);
err:
    return MSG_PROCESS_ERROR;
}

static int
tls_set_client_hello_version(TLS *s)
{
    return 0;
}

int
tls_cipher_list_to_bytes(TLS *s, FC_STACK_OF(TLS_CIPHER) *sk, fc_u8 *p)
{
    const TLS_CIPHER    *c = NULL;
    fc_u8               *q = NULL;
    int                 empty_reneg_info_scsv = !s->tls_renegotiate;
    int                 i = 0;
    int                 j = 0;
    /* Set disabled masks for this session */
    //ssl_set_client_disabled(s);

    if (sk == NULL) {
        return 0;
    }

    q = p;

    for (i = 0; i < sk_TLS_CIPHER_num(sk); i++) {
        c = sk_TLS_CIPHER_value(sk, i);
        /* Skip disabled ciphers */
        if (tls_cipher_disabled(s, c, 0/*TLS_SECOP_CIPHER_SUPPORTED*/, 0)) {
            continue;
        }
        j = s->tls_method->md_put_cipher_by_char(c, p);
        p += j;
    }
    /*
     * If p == q, no ciphers; caller indicates an error. Otherwise, add
     * applicable SCSVs.
     */
    if (p != q) {
        if (empty_reneg_info_scsv) {
#if 0
            static TLS_CIPHER scsv = {
                0, NULL, TLS_CK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            j = s->tls_method->md_put_cipher_by_char(&scsv, p);
            p += j;
#endif
        }
#if 0
        if (s->mode & TLS_MODE_SEND_FALLBACK_SCSV) {
            static TLS_CIPHER scsv = {
                0, NULL, TLS_CK_FALLBACK_SCSV, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            j = s->method->put_cipher_by_char(&scsv, p);
            p += j;
        }
#endif
    }

    return (p - q);
}

static int
tls_construct_client_hello(TLS *s)
{
    //fc_u8       *buf = NULL;
    fc_u8       *p = NULL;
    fc_u8       *d = NULL;
    fc_ulong    l = 0;
    int         protverr = 0;
    int         i = 0;
#if 0
    int         al = 0;
#endif
    TLS_SESSION *sess = s->tls_session;

    //buf = (fc_u8 *)s->tls_init_buf->bm_data;

    /* Work out what SSL/TLS/DTLS version to use */
    protverr = tls_set_client_hello_version(s);
    if (protverr != 0) {
        goto err;
    }

    if ((sess == NULL) /*|| !ssl_version_supported(s, sess->ssl_version) ||
        (!sess->session_id_length && !sess->tlsext_tick) ||
        (sess->not_resumable)*/) {
        if (!tls_get_new_session(s, 0)) {
            FC_LOG("Get new session failed\n");
            goto err;
        }
    }
    /* else use the pre-loaded session */

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

    /* Session ID */
    if (s->tls_new_session) {
        i = 0;
    } else {
        i = s->tls_session->se_session_id_length;
    }
    *(p++) = i;
    if (i != 0) {
        if (i > (int)sizeof(s->tls_session->se_session_id)) {
            goto err;
        }
        memcpy(p, s->tls_session->se_session_id, i);
        p += i;
    }

    /* Ciphers supported */
    i = tls_cipher_list_to_bytes(s, FCTLS_get_ciphers(s), &(p[2]));
    if (i == 0) {
        goto err;
    }
#if 0
    /*
     * Some servers hang if client hello > 256 bytes as hack workaround
     * chop number of supported ciphers to keep it well below this if we
     * use TLS v1.2
     */
    if (TLS1_get_version(s) >= TLS1_2_VERSION
        && i > OPENTLS_MAX_TLS1_2_CIPHER_LENGTH)
        i = OPENTLS_MAX_TLS1_2_CIPHER_LENGTH & ~1;
#endif
    s2n(i, p);
    p += i;

    *(p++) = 1;
    *(p++) = 0;                 /* Add the NULL method */

#if 0
    /* TLS extensions */
    if (ssl_prepare_clienthello_tlsext(s) <= 0) {
        goto err;
    }
    if ((p =
         ssl_add_clienthello_tlsext(s, p, buf + TLS_RT_MAX_PLAIN_LENGTH,
                                    &al)) == NULL) {
        tls_send_alert(s, TLS_AL_FATAL, al);
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
