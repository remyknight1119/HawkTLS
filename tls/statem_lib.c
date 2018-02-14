
#include <falcontls/types.h>
#include <falcontls/buffer.h>

#include <internal/buffer.h>

#include "statem.h"
#include "record_locl.h"
#include "tls_locl.h"
#include "alert.h"

/*
 * send s->init_buf in records of type 'type' (TLS_RT_HANDSHAKE or
 * TLS_RT_CHANGE_CIPHER_SPEC)
 */
int 
tls_do_write(TLS *s, int type)
{
    char    *data = NULL;
    int     ret = 0;

    data = s->tls_init_buf->bm_data;
    ret = s->tls_method->md_tls_write_bytes(s, type, &data[s->tls_init_off],
            s->tls_init_num);
    if (ret < 0) {
        return (-1);
    }

#if 0
    if (type == TLS_RT_HANDSHAKE) {
        /*
         * should not be done for 'Hello Request's, but in that case we'll
         * ignore the result anyway
         */
        if (!tls_finish_mac(s, &data[s->tls_init_off], ret)) {
            return -1;
        }
    }
#endif

    if (ret == s->tls_init_num) {
        return (1);
    }
    s->tls_init_off += ret;
    s->tls_init_num -= ret;
    return (0);
}


int
tls_get_message_header(TLS *s, int *mt)
{
#if 0
    /* s->init_num < TLS_HM_HEADER_LENGTH */
    int skip_message, i, recvd_type, al;
    fc_u8 *p;
    fc_ulong l;

    p = (fc_u8 *)s->init_buf->data;

    do {
        while (s->init_num < TLS_HM_HEADER_LENGTH) {
            i = s->tls_method->md_tls_read_bytes(s, TLS_RT_HANDSHAKE, &recvd_type,
                                          &p[s->init_num],
                                          TLS_HM_HEADER_LENGTH - s->init_num,
                                          0);
            if (i <= 0) {
                s->rwstate = TLS_READING;
                return 0;
            }
            if (recvd_type == TLS_RT_CHANGE_CIPHER_SPEC) {
                /*
                 * A ChangeCipherSpec must be a single byte and may not occur
                 * in the middle of a handshake message.
                 */
                if (s->init_num != 0 || i != 1 || p[0] != TLS_MT_CCS) {
                    al = TLS_AD_UNEXPECTED_MESSAGE;
                    goto f_err;
                }
                s->s3->tmp.message_type = *mt = TLS_MT_CHANGE_CIPHER_SPEC;
                s->init_num = i - 1;
                s->init_msg = s->init_buf->data;
                s->s3->tmp.message_size = i;
                return 1;
            }

            if (recvd_type != TLS_RT_HANDSHAKE) {
                al = TLS_AD_UNEXPECTED_MESSAGE;
                goto f_err;
            }
            s->init_num += i;
        }

        skip_message = 0;
        if (!s->server)
            if (p[0] == TLS_MT_HELLO_REQUEST)
                /*
                 * The server may always send 'Hello Request' messages --
                 * we are doing a handshake anyway now, so ignore them if
                 * their format is correct. Does not count for 'Finished'
                 * MAC.
                 */
                if (p[1] == 0 && p[2] == 0 && p[3] == 0) {
                    s->init_num = 0;
                    skip_message = 1;
                }
    } while (skip_message);
    /* s->init_num == TLS_HM_HEADER_LENGTH */

    *mt = *p;
    s->s3->tmp.message_type = *(p++);
    n2l3(p, l);
    /* BUF_MEM_grow takes an 'int' parameter */
    if (l > (INT_MAX - TLS_HM_HEADER_LENGTH)) {
        al = TLS_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }
    s->s3->tmp.message_size = l;

    s->init_msg = s->init_buf->data + TLS_HM_HEADER_LENGTH;
    s->init_num = 0;

#endif
    return 1;
// f_err:
//    tls_send_alert(s, TLS_AL_FATAL, al);
    return 0;
}

int
tls_get_message_body(TLS *s, fc_ulong *len)
{
#if 0
    long n;
    fc_u8 *p;
    int i;

    if (s->s3->tmp.message_type == TLS_MT_CHANGE_CIPHER_SPEC) {
        /* We've already read everything in */
        *len = (fc_ulong)s->init_num;
        return 1;
    }

    p = s->init_msg;
    n = s->s3->tmp.message_size - s->init_num;
    while (n > 0) {
        i = s->method->ssl_read_bytes(s, TLS_RT_HANDSHAKE, NULL,
                                      &p[s->init_num], n, 0);
        if (i <= 0) {
            s->rwstate = TLS_READING;
            *len = 0;
            return 0;
        }
        s->init_num += i;
        n -= i;
    }

#ifndef OPENTLS_NO_NEXTPROTONEG
    /*
     * If receiving Finished, record MAC of prior handshake messages for
     * Finished verification.
     */
    if (*s->init_buf->data == TLS_MT_FINISHED)
        tls_take_mac(s);
#endif

    /* Feed this message into MAC computation. */
    if (RECORD_LAYER_is_sslv2_record(&s->rlayer)) {
        if (!tls_finish_mac(s, (fc_u8 *)s->init_buf->data,
                             s->init_num)) {
            TLSerr(TLS_F_TLS_GET_MESSAGE_BODY, ERR_R_EVP_LIB);
            tls_send_alert(s, TLS_AL_FATAL, TLS_AD_INTERNAL_ERROR);
            *len = 0;
            return 0;
        }
        if (s->msg_callback)
            s->msg_callback(0, TLS2_VERSION, 0, s->init_buf->data,
                            (size_t)s->init_num, s, s->msg_callback_arg);
    } else {
        if (!tls_finish_mac(s, (fc_u8 *)s->init_buf->data,
                             s->init_num + TLS_HM_HEADER_LENGTH)) {
            TLSerr(TLS_F_TLS_GET_MESSAGE_BODY, ERR_R_EVP_LIB);
            tls_send_alert(s, TLS_AL_FATAL, TLS_AD_INTERNAL_ERROR);
            *len = 0;
            return 0;
        }
    }

    /*
     * init_num should never be negative...should probably be declared
     * unsigned
     */
    if (s->init_num < 0) {
        tls_send_alert(s, TLS_AL_FATAL, TLS_AD_INTERNAL_ERROR);
        *len = 0;
        return 0;
    }
    *len = (fc_ulong)s->init_num;
#endif
    return 1;
}

