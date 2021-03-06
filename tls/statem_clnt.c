#include <string.h>

#include <falcontls/types.h>
#include <falcontls/safestack.h>
#include <falcontls/x509.h>
#include <falcontls/bn.h>
#include <internal/bn.h>
#include <falcontls/dh.h>
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
static MSG_PROCESS_RETURN tls_process_server_certificate(TLS *s, PACKET *pkt);
static MSG_PROCESS_RETURN tls_process_key_exchange(TLS *s, PACKET *pkt);

static const CLIENT_PROCESS tls_statem_client_process[] = {
    {
        .pc_hand_state = TLS_ST_CR_SRVR_HELLO,
        .pc_proc = tls_process_server_hello,
    },
    {
        .pc_hand_state = TLS_ST_CR_CERT,
        .pc_proc = tls_process_server_certificate,
    },
    {
        .pc_hand_state = TLS_ST_CR_KEY_EXCH,
        .pc_proc = tls_process_key_exchange,
    },
};

#define TLS_CLIENT_PROCESS_NUM  FC_ARRAY_SIZE(tls_statem_client_process)

static int tls_construct_client_hello(TLS *s, WPACKET *pkt);

static const CONSTRUCT_MESSAGE tls_state_client_construct[] = {
    {
        .cm_hand_state = TLS_ST_CW_CLNT_HELLO,
        .cm_message_type = TLS1_MT_CHANGE_CIPHER_SPEC,
        .cm_tls_confunc = tls_construct_client_hello,
    },
}

#define TLS_CLIENT_CONSTRUCT_NUM  FC_ARRAY_SIZE(tls_statem_client_construct)

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

    switch (st->sm_hand_state) {
        case TLS_ST_CW_CLNT_HELLO:
            if (mt == TLS1_MT_SERVER_HELLO) {
                st->sm_hand_state = TLS_ST_CR_SRVR_HELLO;
                return 1;
            }

            break;

        case TLS_ST_CR_SRVR_HELLO:
            if (s->tls_hit) {
                if (s->tls_ext_ticket_expected) {
                    if (mt == TLS1_MT_NEWSESSION_TICKET) {
                        st->sm_hand_state = TLS_ST_CR_SESSION_TICKET;
                        return 1;
                    }
                } else if (mt == TLS1_MT_CHANGE_CIPHER_SPEC) {
                    st->sm_hand_state = TLS_ST_CR_CHANGE;
                    return 1;
                }
            } else {
                if (mt == TLS1_MT_CERTIFICATE) {
                    st->sm_hand_state = TLS_ST_CR_CERT;
                    return 1;
                }
                if (mt == TLS1_MT_CERTIFICATE_REQUEST) {
                    st->sm_hand_state = TLS_ST_CR_CERT_REQ;
                    return 1;
                } 
                if (mt == TLS1_MT_SERVER_DONE) {
                    st->sm_hand_state = TLS_ST_CR_SRVR_DONE;
                    return 1;
                }
            }
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
            if (mt == TLS1_MT_SERVER_KEY_EXCHANGE) {
                st->sm_hand_state = TLS_ST_CR_KEY_EXCH;
                return 1;
            }
            goto err;
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
        FC_LOG("Get net 2 failed\n");
        al = TLS_AD_DECODE_ERROR;
        goto f_err;
    }

    protverr = tls_choose_client_version(s, sversion);
    if (protverr != 0) {
        FC_LOG("Choose client version failed\n");
        al = TLS_AD_PROTOCOL_VERSION;
        goto f_err;
    }

    /* load the server hello data */
    /* load the server random */
    if (!PACKET_copy_bytes(pkt, s->tls1.st_server_random, TLS_RANDOM_SIZE)) {
        FC_LOG("Copy server random failed\n");
        al = TLS_AD_DECODE_ERROR;
        goto f_err;
    }

    s->tls_hit = 0;

    /* Get the session-id. */
    if (!PACKET_get_length_prefixed_1(pkt, &session_id)) {
        FC_LOG("Get session id length failed\n");
        al = TLS_AD_DECODE_ERROR;
        goto f_err;
    }
    session = s->tls_session;
    session_id_len = PACKET_remaining(&session_id);
    if (session_id_len > sizeof(session->se_session_id)
        || session_id_len > TLS_SESSION_ID_SIZE) {
        FC_LOG("Session id length invalid(%d)\n", (int)session_id_len);
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }

    if (!PACKET_get_bytes(pkt, &cipherchars, TLS_CIPHER_LEN)) {
        FC_LOG("Get cipher bytes failed\n");
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
            FC_LOG("Session paramter illegal\n");
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
                FC_LOG("Get new session failed\n");
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
        FC_LOG("Get cipher failed\n");
        /* unknown cipher */
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }

    if (tls_cipher_disabled(s, c, 0/*TLS_SECOP_CIPHER_CHECK*/, 1)) {
        FC_LOG("Error: cipher disabled\n");
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }
    sk = tls_get_ciphers_by_id(s);
    i = sk_TLS_CIPHER_find(sk, c);
    if (i < 0) {
        FC_LOG("Find cipher failed, sk = %p\n", sk);
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
        FC_LOG("Cipher id not match\n");
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }
    s->tls_tmp.tm_new_cipher = c;
    /* lets get the compression algorithm */
    /* COMPRESSION */
    if (!PACKET_get_1(pkt, &compression)) {
        FC_LOG("Get compression failed\n");
        al = TLS_AD_DECODE_ERROR;
        goto f_err;
    }

    if (compression != 0) {
        FC_LOG("Compression illegal\n");
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }
    /* TLS extensions */
    if (!tls_parse_serverhello_tlsext(s, pkt)) {
        FC_LOG("Parse serverhello tlsext failed\n");
        goto err;
    }

    if (PACKET_remaining(pkt) != 0) {
        FC_LOG("Error: data remaining\n");
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

static MSG_PROCESS_RETURN
tls_process_server_certificate(TLS *s, PACKET *pkt)
{
    FC_X509                 *x = NULL;
    FC_STACK_OF(FC_X509)    *sk = NULL;
    FC_EVP_PKEY             *pkey = NULL;
    const fc_u8             *certstart = NULL;
    const fc_u8             *certbytes;
    fc_ulong                cert_list_len = 0;
    fc_ulong                cert_len = 0;
    int                     al = 0;
    int                     i = 0;
    int                     exp_idx = 0;
    int                     ret = MSG_PROCESS_ERROR;

    if ((sk = sk_FC_X509_new_null()) == NULL) {
        goto out;
    }

    if (!PACKET_get_net_3(pkt, &cert_list_len)
        || PACKET_remaining(pkt) != cert_list_len) {
        al = TLS_AD_DECODE_ERROR;
        goto f_err;
    }
    while (PACKET_remaining(pkt)) {
        if (!PACKET_get_net_3(pkt, &cert_len)
            || !PACKET_get_bytes(pkt, &certbytes, cert_len)) {
            al = TLS_AD_DECODE_ERROR;
            goto f_err;
        }

        certstart = certbytes;
        x = d2i_FC_X509(NULL, (const fc_u8 **)&certbytes, cert_len);
        if (x == NULL) {
            al = TLS_AD_BAD_CERTIFICATE;
            goto f_err;
        }
        if (certbytes != (certstart + cert_len)) {
            al = TLS_AD_DECODE_ERROR;
            goto f_err;
        }
        if (!sk_FC_X509_push(sk, x)) {
            goto out;
        }
        x = NULL;
    }

    i = tls_verify_cert_chain(s, sk);
    /*
     * The documented interface is that TLS_VERIFY_PEER should be set in order
     * for client side verification of the server certificate to take place.
     * However, historically the code has only checked that *any* flag is set
     * to cause server verification to take place. Use of the other flags makes
     * no sense in client mode. An attempt to clean up the semantics was
     * reverted because at least one application *only* set
     * TLS_VERIFY_FAIL_IF_NO_PEER_CERT. Prior to the clean up this still caused
     * server verification to take place, after the clean up it silently did
     * nothing. TLS_CTX_set_verify()/TLS_set_verify() cannot validate the flags
     * sent to them because they are void functions. Therefore, we now use the
     * (less clean) historic behaviour of performing validation if any flag is
     * set. The *documented* interface remains the same.
     */
    if (s->tls_verify_mode != FC_TLS_VERIFY_NONE && i <= 0) {
        al = tls_verify_alarm_type(s->tls_verify_result);
        goto f_err;
    }

    if (i > 1) {
        al = TLS_AD_HANDSHAKE_FAILURE;
        goto f_err;
    }

    s->tls_session->se_peer_chain = sk;
    /*
     * Inconsistency alert: cert_chain does include the peer's certificate,
     * which we don't include in statem_srvr.c
     */
    x = sk_FC_X509_value(sk, 0);
    sk = NULL;

    pkey = FC_X509_get0_pubkey(x);
    if (pkey == NULL || FC_EVP_PKEY_missing_parameters(pkey)) {
        x = NULL;
        al = TLS_AL_FATAL;
        goto f_err;
    }

    i = tls_cert_type(x, pkey);
    if (i < 0) {
        x = NULL;
        al = TLS_AL_FATAL;
        goto f_err;
    }

    exp_idx = tls_cipher_get_cert_index(s->tls_tmp.tm_new_cipher);
    if (exp_idx >= 0 && i != exp_idx
        && (i != FC_EVP_PKEY_GOST12_512 && i != FC_EVP_PKEY_GOST12_256
             && i != FC_EVP_PKEY_GOST01)) {
        x = NULL;
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }
    s->tls_session->se_peer_type = i;

    FC_X509_free(s->tls_session->se_peer);
    FC_X509_up_ref(x);
    s->tls_session->se_peer = x;
    s->tls_session->se_verify_result = s->tls_verify_result;

    x = NULL;
    ret = MSG_PROCESS_CONTINUE_READING;
    goto out;

 f_err:
    tls_send_alert(s, TLS_AL_FATAL, al);
 out:
    FC_X509_free(x);
    sk_FC_X509_pop_free(sk, FC_X509_free);
    return ret;

}

static int
tls_process_ske_dhe(TLS *s, PACKET *pkt, FC_EVP_PKEY **pkey, int *al)
{
    FC_EVP_PKEY *peer_tmp = NULL;
    FC_DH       *dh = NULL;
    FC_BIGNUM   *p = NULL;
    FC_BIGNUM   *g = NULL;
    FC_BIGNUM   *bnpub_key = NULL;
    PACKET      prime = {};
    PACKET      generator = {};
    PACKET      pub_key = {};
    int         check_bits = 0;

    if (!PACKET_get_length_prefixed_2(pkt, &prime)
        || !PACKET_get_length_prefixed_2(pkt, &generator)
        || !PACKET_get_length_prefixed_2(pkt, &pub_key)) {
        *al = TLS_AD_DECODE_ERROR;
        return 0;
    }

    peer_tmp = FC_EVP_PKEY_new();
    dh = FC_DH_new();

    if (peer_tmp == NULL || dh == NULL) {
        *al = TLS_AD_INTERNAL_ERROR;
        goto err;
    }

    p = FC_BN_bin2bn(PACKET_data(&prime),
            PACKET_remaining(&prime), NULL);
    g = FC_BN_bin2bn(PACKET_data(&generator),
            PACKET_remaining(&generator), NULL);
    bnpub_key = FC_BN_bin2bn(PACKET_data(&pub_key),
            PACKET_remaining(&pub_key),
                          NULL);
    if (p == NULL || g == NULL || bnpub_key == NULL) {
        *al = TLS_AD_INTERNAL_ERROR;
        goto err;
    }

    /* test non-zero pubkey */
    if (FC_BN_is_zero(bnpub_key)) {
        *al = TLS_AD_DECODE_ERROR;
        goto err;
    }

    if (!FC_DH_set0_pqg(dh, p, NULL, g)) {
        *al = TLS_AD_INTERNAL_ERROR;
        goto err;
    }
    p = g = NULL;

    if (FC_DH_check_params(dh, &check_bits) == 0 || check_bits != 0) {
        *al = TLS_AD_DECODE_ERROR;
        goto err;
    }

    if (!FC_DH_set0_key(dh, bnpub_key, NULL)) {
        *al = TLS_AD_INTERNAL_ERROR;
        goto err;
    }
    bnpub_key = NULL;

#if 0
    if (!tls_security(s, TLS_SECOP_TMP_DH, DH_security_bits(dh), 0, dh)) {
        *al = TLS_AD_HANDSHAKE_FAILURE;
        goto err;
    }
#endif

    if (FC_EVP_PKEY_assign_DH(peer_tmp, dh) == 0) {
        *al = TLS_AD_INTERNAL_ERROR;
        goto err;
    }

    s->tls1.st_peer_tmp = peer_tmp;

    /*
     * FIXME: This makes assumptions about which ciphersuites come with
     * public keys. We should have a less ad-hoc way of doing this
     */
    if (s->tls_tmp.tm_new_cipher->cp_algorithm_auth & TLS_aRSA) {
        *pkey = FC_X509_get0_pubkey(s->tls_session->se_peer);
    }
    /* else anonymous DH, so no certificate or pkey. */

    return 1;

 err:
    FC_BN_free(p);
    FC_BN_free(g);
    FC_BN_free(bnpub_key);
    FC_DH_free(dh);
    FC_EVP_PKEY_free(peer_tmp);

    return 0;
}

static int
tls_process_ske_ecdhe(TLS *s, PACKET *pkt, FC_EVP_PKEY **pkey, int *al)
{
    const fc_u8     *ecparams = NULL;
    //FC_EVP_PKEY_CTX *pctx = NULL;
    //PACKET          encoded_pt = {};
    //fc_u32          curve_flags;
    //int             curve_nid;

    /*
     * Extract elliptic curve parameters and the server's ephemeral ECDH
     * public key. For now we only support named (not generic) curves and
     * ECParameters in this case is just three bytes.
     */
    if (!PACKET_get_bytes(pkt, &ecparams, 3)) {
        *al = TLS_AD_DECODE_ERROR;
        FC_LOG("Decode error!\n");
        return 0;
    }
    /*
     * Check curve is one of our preferences, if not server has sent an
     * invalid curve. ECParameters is 3 bytes.
     */
#if 0
    if (!tls1_check_curve(s, ecparams, 3)) {
        *al = TLS_AD_DECODE_ERROR;
        return 0;
    }

    curve_nid = tls1_ec_curve_id2nid(*(ecparams + 2), &curve_flags);

    if (curve_nid == 0) {
        *al = TLS_AD_INTERNAL_ERROR;
        return 0;
    }

    if ((curve_flags & TLS_CURVE_TYPE) == TLS_CURVE_CUSTOM) {
        EVP_PKEY *key = EVP_PKEY_new();

        if (key == NULL || !EVP_PKEY_set_type(key, curve_nid)) {
            *al = TLS_AD_INTERNAL_ERROR;
            SSLerr(TLS_F_TLS_PROCESS_SKE_ECDHE, ERR_R_EVP_LIB);
            EVP_PKEY_free(key);
            return 0;
        }
        s->s3->peer_tmp = key;
    } else {
        /* Set up EVP_PKEY with named curve as parameters */
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (pctx == NULL
            || EVP_PKEY_paramgen_init(pctx) <= 0
            || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid) <= 0
            || EVP_PKEY_paramgen(pctx, &s->s3->peer_tmp) <= 0) {
            *al = TLS_AD_INTERNAL_ERROR;
            SSLerr(TLS_F_TLS_PROCESS_SKE_ECDHE, ERR_R_EVP_LIB);
            EVP_PKEY_CTX_free(pctx);
            return 0;
        }
        EVP_PKEY_CTX_free(pctx);
        pctx = NULL;
    }

    if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt)) {
        *al = TLS_AD_DECODE_ERROR;
        SSLerr(TLS_F_TLS_PROCESS_SKE_ECDHE, TLS_R_LENGTH_MISMATCH);
        return 0;
    }

    if (!EVP_PKEY_set1_tls_encodedpoint(s->s3->peer_tmp,
                                        PACKET_data(&encoded_pt),
                                        PACKET_remaining(&encoded_pt))) {
        *al = TLS_AD_DECODE_ERROR;
        SSLerr(TLS_F_TLS_PROCESS_SKE_ECDHE, TLS_R_BAD_ECPOINT);
        return 0;
    }

    /*
     * The ECC/TLS specification does not mention the use of DSA to sign
     * ECParameters in the server key exchange message. We do support RSA
     * and ECDSA.
     */
    if (s->s3->tmp.new_cipher->algorithm_auth & TLS_aECDSA)
        *pkey = X509_get0_pubkey(s->session->peer);
    else if (s->s3->tmp.new_cipher->algorithm_auth & TLS_aRSA)
        *pkey = X509_get0_pubkey(s->session->peer);
    /* else anonymous ECDH, so no certificate or pkey. */

#endif
    return 1;
}

static MSG_PROCESS_RETURN
tls_process_key_exchange(TLS *s, PACKET *pkt)
{
    FC_EVP_PKEY     *pkey = NULL;
    //PACKET          save_param_start = {};
    //PACKET          signature = {};
    long            alg_k;
    int             al = -1;

    alg_k = s->tls_tmp.tm_new_cipher->cp_algorithm_mkey;

    //save_param_start = *pkt;

#if 0
    EVP_PKEY_free(s->s3->peer_tmp);
    s->s3->peer_tmp = NULL;
#endif

    /* Nothing else to do for plain PSK or RSAPSK */
    if (alg_k & TLS_kDHE) {
        if (!tls_process_ske_dhe(s, pkt, &pkey, &al)) {
            FC_LOG("Process DHE failed!\n");
            goto err;
        }
    } else if (alg_k & TLS_kECDHE) {
        if (!tls_process_ske_ecdhe(s, pkt, &pkey, &al)) {
            FC_LOG("Process ECDHE failed!\n");
            goto err;
        }
    } else if (alg_k) {
        FC_LOG("Unknown alg_k %lu!\n", alg_k);
        al = TLS_AD_UNEXPECTED_MESSAGE;
        goto err;
    }

#if 0
    /* if it was signed, check the signature */
    if (pkey != NULL) {
        PACKET params;
        int maxsig;
        const EVP_MD *md = NULL;
        EVP_MD_CTX *md_ctx;

        /*
         * |pkt| now points to the beginning of the signature, so the difference
         * equals the length of the parameters.
         */
        if (!PACKET_get_sub_packet(&save_param_start, &params,
                                   PACKET_remaining(&save_param_start) -
                                   PACKET_remaining(pkt))) {
            al = TLS_AD_INTERNAL_ERROR;
            SSLerr(TLS_F_TLS_PROCESS_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (TLS_USE_SIGALGS(s)) {
            const unsigned char *sigalgs;
            int rv;
            if (!PACKET_get_bytes(pkt, &sigalgs, 2)) {
                al = TLS_AD_DECODE_ERROR;
                SSLerr(TLS_F_TLS_PROCESS_KEY_EXCHANGE, TLS_R_LENGTH_TOO_SHORT);
                goto err;
            }
            rv = tls12_check_peer_sigalg(&md, s, sigalgs, pkey);
            if (rv == -1) {
                al = TLS_AD_INTERNAL_ERROR;
                goto err;
            } else if (rv == 0) {
                al = TLS_AD_DECODE_ERROR;
                goto err;
            }
        } else if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
            md = EVP_md5_sha1();
        } else {
            md = EVP_sha1();
        }

        if (!PACKET_get_length_prefixed_2(pkt, &signature)
            || PACKET_remaining(pkt) != 0) {
            al = TLS_AD_DECODE_ERROR;
            SSLerr(TLS_F_TLS_PROCESS_KEY_EXCHANGE, TLS_R_LENGTH_MISMATCH);
            goto err;
        }
        maxsig = EVP_PKEY_size(pkey);
        if (maxsig < 0) {
            al = TLS_AD_INTERNAL_ERROR;
            SSLerr(TLS_F_TLS_PROCESS_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        /*
         * Check signature length
         */
        if (PACKET_remaining(&signature) > (size_t)maxsig) {
            /* wrong packet length */
            al = TLS_AD_DECODE_ERROR;
            SSLerr(TLS_F_TLS_PROCESS_KEY_EXCHANGE,
                   TLS_R_WRONG_SIGNATURE_LENGTH);
            goto err;
        }

        md_ctx = EVP_MD_CTX_new();
        if (md_ctx == NULL) {
            al = TLS_AD_INTERNAL_ERROR;
            SSLerr(TLS_F_TLS_PROCESS_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (EVP_VerifyInit_ex(md_ctx, md, NULL) <= 0
            || EVP_VerifyUpdate(md_ctx, &(s->s3->client_random[0]),
                                SSL3_RANDOM_SIZE) <= 0
            || EVP_VerifyUpdate(md_ctx, &(s->s3->server_random[0]),
                                SSL3_RANDOM_SIZE) <= 0
            || EVP_VerifyUpdate(md_ctx, PACKET_data(&params),
                                PACKET_remaining(&params)) <= 0) {
            EVP_MD_CTX_free(md_ctx);
            al = TLS_AD_INTERNAL_ERROR;
            SSLerr(TLS_F_TLS_PROCESS_KEY_EXCHANGE, ERR_R_EVP_LIB);
            goto err;
        }
        if (EVP_VerifyFinal(md_ctx, PACKET_data(&signature),
                            PACKET_remaining(&signature), pkey) <= 0) {
            /* bad signature */
            EVP_MD_CTX_free(md_ctx);
            al = TLS_AD_DECRYPT_ERROR;
            SSLerr(TLS_F_TLS_PROCESS_KEY_EXCHANGE, TLS_R_BAD_SIGNATURE);
            goto err;
        }
        EVP_MD_CTX_free(md_ctx);
    } else {
        /* aNULL, aSRP or PSK do not need public keys */
        if (!(s->s3->tmp.new_cipher->algorithm_auth & (TLS_aNULL | TLS_aSRP))
            && !(alg_k & TLS_PSK)) {
            /* Might be wrong key type, check it */
            if (ssl3_check_cert_and_algorithm(s)) {
                /* Otherwise this shouldn't happen */
                al = TLS_AD_INTERNAL_ERROR;
                SSLerr(TLS_F_TLS_PROCESS_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
            } else {
                al = TLS_AD_DECODE_ERROR;
            }
            goto err;
        }
        /* still data left over */
        if (PACKET_remaining(pkt) != 0) {
            al = TLS_AD_DECODE_ERROR;
            goto err;
        }
    }

#endif
    return MSG_PROCESS_CONTINUE_READING;
 err:
    if (al != -1) {
        tls_send_alert(s, TLS_AL_FATAL, al);
    }
    
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
tls_construct_client_hello(TLS *s, WPACKET *pkt)
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
tls_statem_client_construct_message(TLS *s, WPACKET *pkt,
                confunc_f *confunc, int *mt)
{
    TLS_STATEM  *st = &s->tls_statem;
    int         i = 0;

    for (i = 0; i < TLS_CLIENT_CONSTRUCT_NUM; i++) {
        if (tls_state_client_construct[i].cm_hand_state == st->sm_hand_state) {
            if (TLS_IS_DTLS(s)) {
                *confunc = tls_state_client_construct[i].cm_dtls_confunc;
            } else {
                *confunc = tls_state_client_construct[i].cm_tls_confunc;
            }
            *mt = tls_state_client_construct[i].cm_message_type;
            break;
        }
    }

    return 1;
}
