
#include <falcontls/types.h>
#include <falcontls/buffer.h>
#include <internal/buffer.h>
#include <fc_log.h>

#include "statem.h"
#include "statem_locl.h"
#include "packet.h"
#include "record_locl.h"
#include "tls_locl.h"
#include "alert.h"

/* Sub state machine return values */
typedef enum {
    /* Something bad happened or NBIO */
    SUB_STATE_ERROR,
    /* Sub state finished go to the next sub state */
    SUB_STATE_FINISHED,
    /* Sub state finished and handshake was completed */
    SUB_STATE_END_HANDSHAKE
} SUB_STATE_RETURN;

//static SUB_STATE_RETURN read_state_machine(TLS *s);
//static SUB_STATE_RETURN write_state_machine(TLS *s);

static void
init_read_state_machine(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;

    st->sm_read_state = READ_STATE_HEADER;
}

static void
init_write_state_machine(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;

    st->sm_write_state = WRITE_STATE_TRANSITION;
}

static int
grow_init_buf(TLS *s, size_t size) {

    size_t msg_offset = (char *)s->tls_init_msg - s->tls_init_buf->bm_data;

    if (!FC_BUF_MEM_grow_clean(s->tls_init_buf, (int)size)) {
        return 0;
    }

    if (size < msg_offset) {
        return 0;
    }

    s->tls_init_msg = s->tls_init_buf->bm_data + msg_offset;

    return 1;
}

/*
 * Send a previously constructed message to the peer.
 */
static int
statem_do_write(TLS *s)
{
    TLS_STATEM  *st = &s->tls_statem;

    if (st->sm_hand_state == TLS_ST_CW_CHANGE
            || st->sm_hand_state == TLS_ST_SW_CHANGE) {
        return tls_do_write(s, TLS_RT_CHANGE_CIPHER_SPEC);
    }

    return tls_do_write(s, TLS_RT_HANDSHAKE);
}


static SUB_STATE_RETURN
read_state_machine(TLS *s)
{
    TLS_STATEM          *st = &s->tls_statem;
    int                 (*transition)(TLS *s, int mt);
    MSG_PROCESS_RETURN  (*process_message)(TLS *s, PACKET *pkt);
    WORK_STATE          (*post_process_message)(TLS *s, WORK_STATE wst);
    fc_ulong            (*max_message_size) (TLS *s);
    int                 ret = 0;
    int                 mt = 0;
    fc_ulong            len = 0;
    PACKET              pkt = {};

    if (s->tls_server) {
        transition = tls_statem_server_read_transition;
        process_message = tls_statem_server_process_message;
        max_message_size = tls_statem_server_max_message_size;
        post_process_message = tls_statem_server_post_process_message;
    } else {
        transition = tls_statem_client_read_transition;
        process_message = tls_statem_client_process_message;
        max_message_size = tls_statem_client_max_message_size;
        post_process_message = tls_statem_client_post_process_message;
    }

    if (st->sm_read_state_first_init) {
        s->tls_first_packet = 1;
        st->sm_read_state_first_init = 0;
    }

    while (1) {
        switch (st->sm_read_state) {
        case READ_STATE_HEADER:
            /* Get the state the peer wants to move to */
            ret = tls_get_message_header(s, &mt);

            if (ret == 0) {
                /* Could be non-blocking IO */
                FC_LOG("Get message header failed!\n");
                return SUB_STATE_ERROR;
            }

            /*
             * Validate that we are allowed to move to the new state and move
             * to that state if so
             */
            if (!transition(s, mt)) {
                FC_LOG("Transition failed!\n");
                return SUB_STATE_ERROR;
            }

            if (s->tls_tmp.tm_message_size > max_message_size(s)) {
                tls_send_alert(s, TLS_AL_FATAL, TLS_AD_ILLEGAL_PARAMETER);
                FC_LOG("Size too big(message_size = %lu, max_size = %lu)!\n",
                        s->tls_tmp.tm_message_size, max_message_size(s));
                return SUB_STATE_ERROR;
            }

            if (s->tls_tmp.tm_message_size > 0
                    && !grow_init_buf(s, s->tls_tmp.tm_message_size
                                         + TLS_HM_HEADER_LENGTH)) {
                tls_send_alert(s, TLS_AL_FATAL, TLS_AD_INTERNAL_ERROR);
                FC_LOG("Grow buffer failed!\n");
                return SUB_STATE_ERROR;
            }

            st->sm_read_state = READ_STATE_BODY;
            /* Fall through */

        case READ_STATE_BODY:
            ret = tls_get_message_body(s, &len);
            if (ret == 0) {
                FC_LOG("Get message body failed!\n");
                return SUB_STATE_ERROR;
            }

            s->tls_first_packet = 0;
            if (!PACKET_buf_init(&pkt, s->tls_init_msg, len)) {
                tls_send_alert(s, TLS_AL_FATAL, TLS_AD_INTERNAL_ERROR);
                FC_LOG("Init paket buffer failed!\n");
                return SUB_STATE_ERROR;
            }
            ret = process_message(s, &pkt);

            /* Discard the packet data */
            s->tls_init_num = 0;

            switch (ret) {
            case MSG_PROCESS_ERROR:
                FC_LOG("MSG_PROCESS_ERROR\n");
                return SUB_STATE_ERROR;

            case MSG_PROCESS_FINISHED_READING:
                return SUB_STATE_FINISHED;

            case MSG_PROCESS_CONTINUE_PROCESSING:
                st->sm_read_state = READ_STATE_POST_PROCESS;
                st->sm_read_state_work = WORK_MORE_A;
                break;

            default:
                st->sm_read_state = READ_STATE_HEADER;
                break;
            }
            break;

        case READ_STATE_POST_PROCESS:
            st->sm_read_state_work = post_process_message(s,
                    st->sm_read_state_work);
            switch (st->sm_read_state_work) {
            case WORK_FINISHED_CONTINUE:
                st->sm_read_state = READ_STATE_HEADER;
                break;

            case WORK_FINISHED_STOP:
                return SUB_STATE_FINISHED;

            default:
                FC_LOG("READ STATE POST PROCESS failed!\n");
                return SUB_STATE_ERROR;
            }
            break;

        default:
            /* Shouldn't happen */
            tls_send_alert(s, TLS_AL_FATAL, TLS_AD_INTERNAL_ERROR);
            return SUB_STATE_ERROR;
        }
    }
}

static SUB_STATE_RETURN
write_state_machine(TLS *s)
{
    TLS_STATEM      *st = &s->tls_statem;
    WRITE_TRAN      (*transition)(TLS *s);
    WORK_STATE      (*pre_work)(TLS *s, WORK_STATE wst);
    WORK_STATE      (*post_work)(TLS *s, WORK_STATE wst);
    int             (*construct_message)(TLS *s, WPACKET *pkt,          
                        int (**confunc) (TLS *s, WPACKET *pkt),
                        int *mt);
    int             (*confunc) (TLS *s, WPACKET *pkt);
    WPACKET         pkt;
    int             mt;
    int             ret = 0;

    if (s->tls_server) {
        transition = tls_statem_server_write_transition;
        pre_work = tls_statem_server_pre_work;
        post_work = tls_statem_server_post_work;
        construct_message = tls_statem_server_construct_message;
    } else {
        transition = tls_statem_client_write_transition;
        pre_work = tls_statem_client_pre_work;
        post_work = tls_statem_client_post_work;
        construct_message = tls_statem_client_construct_message;
    }

    while (1) {
        switch (st->sm_write_state) {
        case WRITE_STATE_TRANSITION:
            switch (transition(s)) {
            case WRITE_TRAN_CONTINUE:
                st->sm_write_state = WRITE_STATE_PRE_WORK;
                st->sm_write_state_work = WORK_MORE_A;
                break;

            case WRITE_TRAN_FINISHED:
                return SUB_STATE_FINISHED;

            default:
                FC_LOG("Error\n");
                return SUB_STATE_ERROR;
            }
            break;

        case WRITE_STATE_PRE_WORK:
            switch (st->sm_write_state_work = pre_work(s,
                        st->sm_write_state_work)) {
            default:
                FC_LOG("Error\n");
                return SUB_STATE_ERROR;

            case WORK_FINISHED_CONTINUE:
                st->sm_write_state = WRITE_STATE_SEND;
                break;

            case WORK_FINISHED_STOP:
                return SUB_STATE_END_HANDSHAKE;
            }
            if (construct_message(s, &pkt, &confunc, &mt) == 0) {
                FC_LOG("Error\n");
                return SUB_STATE_ERROR;
            }

#if 0
            if (mt == SSL3_MT_DUMMY) {
                /* Skip construction and sending. This isn't a "real" state */
                st->write_state = WRITE_STATE_POST_WORK;
                st->write_state_work = WORK_MORE_A;
                break;
            }
#endif
            if (!WPACKET_init(&pkt, s->tls_init_buf)
                    || !tls_set_handshake_header(s, &pkt, mt)) {
                WPACKET_cleanup(&pkt);
                return SUB_STATE_ERROR;
            }
            if (confunc != NULL && !confunc(s, &pkt)) {
                WPACKET_cleanup(&pkt);
                return SUB_STATE_ERROR;
            }
            if (!ssl_close_construct_packet(s, &pkt, mt)
                    || !WPACKET_finish(&pkt)) {
                WPACKET_cleanup(&pkt);
                return SUB_STATE_ERROR;
            }

            /* Fall through */

        case WRITE_STATE_SEND:
            ret = statem_do_write(s);
            if (ret <= 0) {
                FC_LOG("Error\n");
                return SUB_STATE_ERROR;
            }
            st->sm_write_state = WRITE_STATE_POST_WORK;
            st->sm_write_state_work = WORK_MORE_A;
            /* Fall through */

        case WRITE_STATE_POST_WORK:
            switch (st->sm_write_state_work = post_work(s, 
                        st->sm_write_state_work)) {
            default:
                FC_LOG("Error\n");
                return SUB_STATE_ERROR;

            case WORK_FINISHED_CONTINUE:
                st->sm_write_state = WRITE_STATE_TRANSITION;
                break;

            case WORK_FINISHED_STOP:
                return SUB_STATE_END_HANDSHAKE;
            }
            break;

        default:
            FC_LOG("Error\n");
            return SUB_STATE_ERROR;
        }
    }
}

TLS_HANDSHAKE_STATE 
TLS_get_state(const TLS *s)
{
    return s->tls_statem.sm_hand_state;
}

void 
tls_statem_clear(TLS *s)
{
    s->tls_statem.sm_state = MSG_FLOW_UNINITED;
    s->tls_statem.sm_hand_state = TLS_ST_BEFORE;
    s->tls_statem.sm_in_init = 1;
}

static int
tls_state_machine(TLS *s, int server)
{
    TLS_STATEM  *st = &s->tls_statem;
    FC_BUF_MEM  *buf = NULL;
    int         ssret = 0;
    int         ret = -1;

    st->sm_in_handshake++;
    if (st->sm_state == MSG_FLOW_UNINITED || 
            st->sm_state == MSG_FLOW_RENEGOTIATE) {
        if (st->sm_state == MSG_FLOW_UNINITED) {
            st->sm_hand_state = TLS_ST_BEFORE;
        }
        s->tls_server = server;
        if (s->tls_init_buf == NULL) {
            if ((buf = FC_BUF_MEM_new()) == NULL) {
                FC_LOG("New mem buf failed!\n");
                goto end;
            }
            if (!FC_BUF_MEM_grow(buf, FC_TLS_RT_MAX_PLAIN_LENGTH)) {
                FC_LOG("Grow mem buf failed!\n");
                goto end;
            }
            s->tls_init_buf = buf;
            buf = NULL;
        }

        if (!tls_setup_buffers(s)) {
            FC_LOG("setup buffers failed!\n");
            goto end;
        }

        s->tls_init_num = 0;

        if (server) {
        } else {
            s->tls_hit = 0;
        }
        st->sm_state = MSG_FLOW_WRITING;
        init_write_state_machine(s);
        st->sm_read_state_first_init = 1;
    }

    while (st->sm_state != MSG_FLOW_FINISHED) {
        if (st->sm_state == MSG_FLOW_READING) {
            ssret = read_state_machine(s);
            if (ssret == SUB_STATE_FINISHED) {
                st->sm_state = MSG_FLOW_WRITING;
                init_write_state_machine(s);
            } else {
                FC_LOG("Read error!\n");
                goto end;
            }
        } else if (st->sm_state == MSG_FLOW_WRITING) {
            ssret = write_state_machine(s);
            if (ssret == SUB_STATE_FINISHED) {
                st->sm_state = MSG_FLOW_READING;
                init_read_state_machine(s);
            } else if (ssret == SUB_STATE_END_HANDSHAKE) {
                st->sm_state = MSG_FLOW_FINISHED;
            } else {
                FC_LOG("Write error, ret = %d!\n", ssret);
                goto end;
            }
        } else {
            FC_LOG("State error!\n");
            goto end;
        }
    }

    st->sm_state = MSG_FLOW_UNINITED;
    ret = 1;
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
TLS_in_init(TLS *s)
{
    return s->tls_statem.sm_in_init;
}

int
TLS_is_init_finished(TLS *s)
{
    return !(s->tls_statem.sm_in_init) && 
        (s->tls_statem.sm_hand_state == TLS_ST_OK);
}

int
TLS_in_before(TLS *s)
{
    /*
     * Historically being "in before" meant before anything had happened. In the
     * current code though we remain in the "before" state for a while after we
     * have started the handshake process (e.g. as a server waiting for the
     * first message to arrive). There "in before" is taken to mean "in before"
     * and not started any handshake process yet.
     */
    return (s->tls_statem.sm_hand_state == TLS_ST_BEFORE)
        && (s->tls_statem.sm_state == MSG_FLOW_UNINITED);
}

int
tls_statem_get_in_handshake(TLS *s)
{
    return s->tls_statem.sm_in_handshake; 
}

void
tls_statem_init(void)
{
    tls_statem_client_init();
}

