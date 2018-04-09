#include <string.h>

#include <falcontls/tls.h>
#include <falcontls/bio.h>
#include <fc_log.h>

#include "statem.h"
#include "tls_locl.h"
#include "tls1.h"
#include "tls1_2.h"
#include "record_locl.h"
#include "alert.h"

int
tls1_2_read_bytes(TLS *s, int type, int *recvd_type, fc_u8 *buf,
        int len, int peek)
{
    TLS_RECORD      *rr = NULL;
    TLS_BUFFER      *rbuf = NULL;
    RECORD_LAYER    *rlayer = NULL;
    fc_u8           *dest = NULL;
    fc_u32          *dest_len = NULL;
    fc_u32          dest_maxlen = 0;
    fc_u32          n = 0;
    fc_u32          curr_rec = 0;
    fc_u32          num_recs = 0;
    fc_u32          read_bytes = 0;
    int             al = 0;
    int             i = 0;
    int             ret = 0;

    rlayer = &s->tls_rlayer;
    rbuf = &rlayer->rl_rbuf;
    if (!TLS_BUFFER_is_initialised(rbuf)) {
        /* Not initialized yet */
        if (!tls_setup_read_buffer(s)) {
            return (-1);
        }
    }

    if ((type && (type != TLS_RT_APPLICATION_DATA)
         && (type != TLS_RT_HANDSHAKE)) || 
            (peek && (type != TLS_RT_APPLICATION_DATA))) {
        return -1;
    }

    if ((type == TLS_RT_HANDSHAKE) && (rlayer->rl_handshake_fragment_len > 0)) {
        /* (partially) satisfy request from storage */
        fc_u8 *src = rlayer->rl_handshake_fragment;
        fc_u8 *dst = buf;
        fc_u32 k = 0;

        /* peek == 0 */
        n = 0;
        while ((len > 0) && (rlayer->rl_handshake_fragment_len > 0)) {
            *dst++ = *src++;
            len--;
            rlayer->rl_handshake_fragment_len--;
            n++;
        }
        /* move any remaining fragment bytes: */
        for (k = 0; k < rlayer->rl_handshake_fragment_len; k++) {
            rlayer->rl_handshake_fragment[k] = *src++;
        }

        if (recvd_type != NULL) {
            *recvd_type = TLS_RT_HANDSHAKE;
        }

        return n;
    }

    /*
     * Now s->tls_rlayer.rl_handshake_fragment_len == 0 
     * if type == TLS_RT_HANDSHAKE.
     */

    if (!tls_statem_get_in_handshake(s) && TLS_in_init(s)) {
        /* type == TLS_RT_APPLICATION_DATA */
        i = s->tls_handshake_func(s);
        if (i < 0) {
            return (i);
        }
        if (i == 0) {
            return (-1);
        }
    }

start:
    s->tls_rwstate = TLS_NOTHING;

    /*-
     * For each record 'i' up to |num_recs]
     * rr[i].type     - is the type of record
     * rr[i].data,    - data
     * rr[i].off,     - offset into 'data' for next read
     * rr[i].length,  - number of bytes.
     */
    rr = rlayer->rl_rrec;
    num_recs = RECORD_LAYER_get_numrpipes(rlayer);

    do {
        /* get new records if necessary */
        if (num_recs == 0) {
            ret = tls_get_record(s);
            if (ret <= 0) {
                return (ret);
            }
            num_recs = RECORD_LAYER_get_numrpipes(rlayer);
            if (num_recs == 0) {
                /* Shouldn't happen */
                al = TLS_AD_INTERNAL_ERROR;
                goto f_err;
            }
        }
        /* Skip over any records we have already read */
        for (curr_rec = 0;
             curr_rec < num_recs && TLS_RECORD_is_read(&rr[curr_rec]);
             curr_rec++);
        if (curr_rec == num_recs) {
            RECORD_LAYER_set_numrpipes(rlayer, 0);
            num_recs = 0;
            curr_rec = 0;
        }
    } while (num_recs == 0);
    rr = &rr[curr_rec];

    /*
     * Reset the count of consecutive warning alerts if we've got a non-empty
     * record that isn't an alert.
     */
    if (TLS_RECORD_get_type(rr) != TLS_RT_ALERT
            && TLS_RECORD_get_length(rr) != 0) {
        rlayer->rl_alert_count = 0;
    }

    /* we now have a packet which can be read and processed */

    if (s->tls1.st_change_cipher_spec /* set when we receive ChangeCipherSpec,
                                   * reset by tls1_2_get_finished */
        && (TLS_RECORD_get_type(rr) != TLS_RT_HANDSHAKE)) {
        al = TLS_AD_UNEXPECTED_MESSAGE;
        goto f_err;
    }

    /*
     * If the other end has shut down, throw anything we read away (even in
     * 'peek' mode)
     */
    if (s->tls_shutdown & TLS_RECEIVED_SHUTDOWN) {
        TLS_RECORD_set_length(rr, 0);
        s->tls_rwstate = TLS_NOTHING;
        return (0);
    }

    if (type == TLS_RECORD_get_type(rr)
        || (TLS_RECORD_get_type(rr) == TLS_RT_CHANGE_CIPHER_SPEC
            && type == TLS_RT_HANDSHAKE && recvd_type != NULL)) {
        /*
         * TLS_RT_APPLICATION_DATA or
         * TLS_RT_HANDSHAKE or
         * TLS_RT_CHANGE_CIPHER_SPEC
         */
        /*
         * make sure that we are not getting application data when we are
         * doing a handshake for the first time
         */
        if (TLS_in_init(s) && (type == TLS_RT_APPLICATION_DATA)/* &&
            (s->enc_read_ctx == NULL)*/) {
            al = TLS_AD_UNEXPECTED_MESSAGE;
            goto f_err;
        }

        if (type == TLS_RT_HANDSHAKE
            && TLS_RECORD_get_type(rr) == TLS_RT_CHANGE_CIPHER_SPEC
            && rlayer->rl_handshake_fragment_len > 0) {
            al = TLS_AD_UNEXPECTED_MESSAGE;
            goto f_err;
        }

        if (recvd_type != NULL) {
            *recvd_type = TLS_RECORD_get_type(rr);
        }

        if (len <= 0) {
            return (len);
        }

        read_bytes = 0;
        do {
            if ((fc_u32)len - read_bytes > TLS_RECORD_get_length(rr)) {
                n = TLS_RECORD_get_length(rr);
            } else {
                n = (fc_u32)len - read_bytes;
            }

            memcpy(buf, &(rr->rd_data[rr->rd_off]), n);
            buf += n;
            if (peek) {
                /* Mark any zero length record as consumed CVE-2016-6305 */
                if (TLS_RECORD_get_length(rr) == 0) {
                    TLS_RECORD_set_read(rr);
                }
            } else {
                TLS_RECORD_sub_length(rr, n);
                TLS_RECORD_add_off(rr, n);
                if (TLS_RECORD_get_length(rr) == 0) {
                    rlayer->rl_rstate = TLS_ST_READ_HEADER;
                    TLS_RECORD_set_off(rr, 0);
                    TLS_RECORD_set_read(rr);
                }
            }
            if (TLS_RECORD_get_length(rr) == 0
                || (peek && n == TLS_RECORD_get_length(rr))) {
                curr_rec++;
                rr++;
            }
            read_bytes += n;
        } while (type == TLS_RT_APPLICATION_DATA && curr_rec < num_recs
                 && read_bytes < (fc_u32)len);
        if (read_bytes == 0) {
            /* We must have read empty records. Get more data */
            goto start;
        }
        if (!peek && curr_rec == num_recs
            && (s->tls_mode & TLS_MODE_RELEASE_BUFFERS)
            && TLS_BUFFER_get_left(rbuf) == 0) {
            tls_release_read_buffer(s);
        }
        return read_bytes;
    }

    /*
     * In case of record types for which we have 'fragment' storage, fill
     * that so that we can process the data at a fixed place.
     */
    if (TLS_RECORD_get_type(rr) == TLS_RT_HANDSHAKE) {
        dest_maxlen = sizeof(rlayer->rl_handshake_fragment);
        dest = rlayer->rl_handshake_fragment;
        dest_len = &rlayer->rl_handshake_fragment_len;
    } else if (TLS_RECORD_get_type(rr) == TLS_RT_ALERT) {
        dest_maxlen = sizeof(rlayer->rl_alert_fragment);
        dest = rlayer->rl_alert_fragment;
        dest_len = &rlayer->rl_alert_fragment_len;
    }

    if (dest_maxlen > 0) {
        n = dest_maxlen - *dest_len; /* available space in 'dest' */
        if (TLS_RECORD_get_length(rr) < n) {
            n = TLS_RECORD_get_length(rr); /* available bytes */
        }

        /* now move 'n' bytes: */
        while (n-- > 0) {
            dest[(*dest_len)++] =
                TLS_RECORD_get_data(rr)[TLS_RECORD_get_off(rr)];
            TLS_RECORD_add_off(rr, 1);
            TLS_RECORD_add_length(rr, -1);
        }

        if (*dest_len < dest_maxlen) {
            TLS_RECORD_set_read(rr);
            goto start;     /* fragment was too small */
        }
    }

    /*-
     * s->rlayer.handshake_fragment_len == 4  iff  rr->type == TLS_RT_HANDSHAKE;
     * s->rlayer.alert_fragment_len == 2      iff  rr->type == TLS_RT_ALERT.
     * (Possibly rr is 'empty' now, i.e. rr->length may be 0.)
     */

    /* If we are a client, check for an incoming 'Hello Request': */
    if ((!s->tls_server) &&
        (rlayer->rl_handshake_fragment_len >= 4) &&
        (rlayer->rl_handshake_fragment[0] == TLS1_MT_HELLO_REQUEST) &&
        (s->tls_session != NULL) && (s->tls_session->se_ciphers != NULL)) {
        rlayer->rl_handshake_fragment_len = 0;

        if ((rlayer->rl_handshake_fragment[1] != 0) ||
            (rlayer->rl_handshake_fragment[2] != 0) ||
            (rlayer->rl_handshake_fragment[3] != 0)) {
            al = TLS_AD_DECODE_ERROR;
            goto f_err;
        }

        /*
         * we either finished a handshake or ignored the request, now try
         * again to obtain the (application) data we were asked for
         */
        goto start;
    }
    /*
     * If we are a server and get a client hello when renegotiation isn't
     * allowed send back a no renegotiation alert and carry on. WARNING:
     * experimental code, needs reviewing (steve)
     */
    if (s->tls_server &&
        TLS_is_init_finished(s) &&
        !s->tls1.st_send_connection_binding &&
        (rlayer->rl_handshake_fragment_len >= 4) &&
        (rlayer->rl_handshake_fragment[0] == TLS1_MT_CLIENT_HELLO) &&
        (s->tls_session != NULL) && (s->tls_session->se_ciphers != NULL)) {
        TLS_RECORD_set_length(rr, 0);
        TLS_RECORD_set_read(rr);
        tls_send_alert(s, TLS_AL_WARNING, TLS_AD_NO_RENEGOTIATION);
        goto start;
    }

    if (rlayer->rl_alert_fragment_len >= 2) {
        int alert_level = rlayer->rl_alert_fragment[0];
        int alert_descr = rlayer->rl_alert_fragment[1];

        rlayer->rl_alert_fragment_len = 0;

        if (alert_level == TLS_AL_WARNING) {
            //s->tls1.st_warn_alert = alert_descr;
            TLS_RECORD_set_read(rr);

            rlayer->rl_alert_count++;
            if (rlayer->rl_alert_count == MAX_WARN_ALERT_COUNT) {
                al = TLS_AD_UNEXPECTED_MESSAGE;
                goto f_err;
            }

            if (alert_descr == TLS_AD_CLOSE_NOTIFY) {
                s->tls_shutdown |= TLS_RECEIVED_SHUTDOWN;
                return (0);
            }
            /*
             * This is a warning but we receive it if we requested
             * renegotiation and the peer denied it. Terminate with a fatal
             * alert because if application tried to renegotiate it
             * presumably had a good reason and expects it to succeed. In
             * future we might have a renegotiation where we don't care if
             * the peer refused it where we carry on.
             */
            else if (alert_descr == TLS_AD_NO_RENEGOTIATION) {
                al = TLS_AD_HANDSHAKE_FAILURE;
                goto f_err;
            }
        } else if (alert_level == TLS_AL_FATAL) {
            s->tls_rwstate = TLS_NOTHING;
            //s->tls1.st_fatal_alert = alert_descr;
            s->tls_shutdown |= TLS_RECEIVED_SHUTDOWN;
            TLS_RECORD_set_read(rr);
            //TLS_CTX_remove_session(s->tls_session_ctx, s->tls_session);
            return (0);
        } else {
            al = TLS_AD_ILLEGAL_PARAMETER;
            goto f_err;
        }

        goto start;
    }

    if (s->tls_shutdown & TLS_SENT_SHUTDOWN) { /* but we have not received a
                                            * shutdown */
        s->tls_rwstate = TLS_NOTHING;
        TLS_RECORD_set_length(rr, 0);
        TLS_RECORD_set_read(rr);
        return (0);
    }

    if (TLS_RECORD_get_type(rr) == TLS_RT_CHANGE_CIPHER_SPEC) {
        al = TLS_AD_UNEXPECTED_MESSAGE;
        goto f_err;
    }

    /*
     * Unexpected handshake message (Client Hello, or protocol violation)
     */
    if ((rlayer->rl_handshake_fragment_len >= 4)
        && !tls_statem_get_in_handshake(s)) {
        i = s->tls_handshake_func(s);
        if (i < 0) {
            return (i);
        }
        if (i == 0) {
            return (-1);
        }

        goto start;
    }

    switch (TLS_RECORD_get_type(rr)) {
    default:
        /*
         * TLS 1.0 and 1.1 say you SHOULD ignore unrecognised record types, but
         * TLS 1.2 says you MUST send an unexpected message alert. We use the
         * TLS 1.2 behaviour for all protocol versions to prevent issues where
         * no progress is being made and the peer continually sends unrecognised
         * record types, using up resources processing them.
         */
        al = TLS_AD_UNEXPECTED_MESSAGE;
        goto f_err;
    case TLS_RT_CHANGE_CIPHER_SPEC:
    case TLS_RT_ALERT:
    case TLS_RT_HANDSHAKE:
        /*
         * we already handled all of these, with the possible exception of
         * TLS_RT_HANDSHAKE when ossl_statem_get_in_handshake(s) is true, but
         * that should not happen when type != rr->type
         */
        al = TLS_AD_UNEXPECTED_MESSAGE;
        goto f_err;
    case TLS_RT_APPLICATION_DATA:
        al = TLS_AD_UNEXPECTED_MESSAGE;
        goto f_err;
    }
    /* not reached */

 f_err:
    tls_send_alert(s, TLS_AL_FATAL, al);
    return (-1);
}

static int 
tls1_2_write_pending(TLS *s, int type, const fc_u8 *buf, fc_u32 len)
{
    TLS_BUFFER      *wb = s->tls_rlayer.rl_wbuf;
    fc_u32          currbuf = 0;
    int             i = 0;

    if ((s->tls_rlayer.rl_wpend_tot > (int)len)
        || ((s->tls_rlayer.rl_wpend_buf != buf)/* &&
            !(s->mode & TLS_MODE_ACCEPT_MOVING_WRITE_BUFFER)*/)
        || (s->tls_rlayer.rl_wpend_type != type)) {
        return (-1);
    }

    for (;;) {
        /* Loop until we find a buffer we haven't written out yet */
        if (TLS_BUFFER_get_left(&wb[currbuf]) == 0
            && currbuf < s->tls_rlayer.rl_numwpipes - 1) {
            currbuf++;
            continue;
        }

        if (s->tls_wbio != NULL) {
            s->tls_rwstate = TLS_WRITING;
            i = FC_BIO_write(s->tls_wbio, (char *)
                          &(TLS_BUFFER_get_buf(&wb[currbuf])
                            [TLS_BUFFER_get_offset(&wb[currbuf])]),
                          (fc_u32)TLS_BUFFER_get_left(&wb[currbuf]));
        } else {
            i = -1;
        }

        if (i == TLS_BUFFER_get_left(&wb[currbuf])) {
            TLS_BUFFER_set_left(&wb[currbuf], 0);
            TLS_BUFFER_add_offset(&wb[currbuf], i);
            if (currbuf + 1 < s->tls_rlayer.rl_numwpipes) {
                continue;
            }
            s->tls_rwstate = TLS_NOTHING;
            return (s->tls_rlayer.rl_wpend_ret);
        } 
        
        if (i <= 0) {
            return i;
        }
        TLS_BUFFER_add_offset(&wb[currbuf], i);
        TLS_BUFFER_add_left(&wb[currbuf], -i);
    }
}

static int
do_tls1_2_write(TLS *s, int type, const fc_u8 *buf, fc_u32 *pipelens, 
        fc_u32 numpipes, int create_empty_fragment)
{
    TLS_BUFFER  *wb = NULL;
    TLS_SESSION *sess = NULL;
    fc_u8       *outbuf[FC_TLS_MAX_PIPELINES] = {};
    fc_u8       *plen[FC_TLS_MAX_PIPELINES] = {};
    TLS_RECORD  wr[FC_TLS_MAX_PIPELINES] = {};
    int         i = 0;
    int         mac_size = 1;
    //int         clear = 0;
    int         prefix_len = 0;
    int         eivlen = 0;
    size_t      align = 0;
    fc_u32      totlen = 0;
    fc_u32      j = 0;

    FC_LOG("in\n");
    for (j = 0; j < numpipes; j++) {
        totlen += pipelens[j];
    }

    /*
     * first check if there is a TLS_BUFFER still being written out.  This
     * will happen with non blocking IO
     */
    if (RECORD_LAYER_write_pending(&s->tls_rlayer)) {
        return (tls1_2_write_pending(s, type, buf, totlen));
    }

    /* If we have an alert to send, lets send it */
    if (s->tls1.st_alert_dispatch) {
        i = s->tls_method->md_tls_dispatch_alert(s);
        if (i <= 0) {
            return (i);
        }
        /* if it went, fall through and send more stuff */
    }

    if (s->tls_rlayer.rl_numwpipes < numpipes)
        if (!tls_setup_write_buffer(s, numpipes, 0)) {
            return -1;
        }

    if (totlen == 0 && !create_empty_fragment) {
        return 0;
    }

    sess = s->tls_session;
    if ((sess == NULL) || (s->tls_enc_write_ctx == NULL)
            /* || (EVP_MD_CTX_md(s->write_hash) == NULL)*/) {
        //clear = /*s->enc_write_ctx ? 0 : */1; /* must be AEAD cipher */
        mac_size = 0;
    } else {
        //mac_size = EVP_MD_CTX_size(s->write_hash);
        if (mac_size < 0) {
            goto err;
        }
    }

    /*
     * 'create_empty_fragment' is true only when this function calls itself
     */
#if 0
    if (!clear && !create_empty_fragment && !s->s3->empty_fragment_done) {
        if (s->s3->need_empty_fragments && type == TLS3_RT_APPLICATION_DATA) {
            /*
             * recursive function call with 'create_empty_fragment' set; this
             * prepares and buffers the data for an empty fragment (these
             * 'prefix_len' bytes are sent out later together with the actual
             * payload)
             */
            fc_u32 tmppipelen = 0;

            prefix_len = do_tls1_2_write(s, type, buf, &tmppipelen, 1, 1);
            if (prefix_len <= 0)
                goto err;

            if (prefix_len >
                (TLS3_RT_HEADER_LENGTH + TLS3_RT_SEND_MAX_ENCRYPTED_OVERHEAD)) {
                /* insufficient space */
                TLSerr(TLS_F_DO_TLS3_WRITE, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }

        s->s3->empty_fragment_done = 1;
    }
#endif

    if (create_empty_fragment) {
        wb = &s->tls_rlayer.rl_wbuf[0];
        outbuf[0] = TLS_BUFFER_get_buf(wb) + align;
        TLS_BUFFER_set_offset(wb, align);
    } else if (prefix_len) {
        wb = &s->tls_rlayer.rl_wbuf[0];
        outbuf[0] = TLS_BUFFER_get_buf(wb) + TLS_BUFFER_get_offset(wb)
            + prefix_len;
    } else {
        for (j = 0; j < numpipes; j++) {
            wb = &s->tls_rlayer.rl_wbuf[j];
            outbuf[j] = TLS_BUFFER_get_buf(wb) + align;
            TLS_BUFFER_set_offset(wb, align);
        }
    }

    /* Explicit IV length, block ciphers appropriate version flag */
    if (s->tls_enc_write_ctx && TLS_USE_EXPLICIT_IV(s)) {
#if 0
        int mode = EVP_CIPHER_CTX_mode(s->enc_write_ctx);
        /* Need explicit part of IV for GCM mode */
        if (mode == EVP_CIPH_GCM_MODE || mode == EVP_CIPH_CCM_MODE) {
            eivlen = EVP_CCM_TLS_EXPLICIT_IV_LEN;
        } else {
            eivlen = 0;
        }
#endif
    } else {
        eivlen = 0;
    }

    totlen = 0;
    for (j = 0; j < numpipes; j++) {
        /* write the header */
        *(outbuf[j]++) = type & 0xff;
        TLS_RECORD_set_type(&wr[j], type);

        *(outbuf[j]++) = (s->tls_version >> 8);
        /*
         * Some servers hang if initial client hello is larger than 256 bytes
         * and record version number > TLS 1.0
         */
        if (TLS_get_state(s) == TLS_ST_CW_CLNT_HELLO
            /*&& !s->renegotiate*/) {
            *(outbuf[j]++) = 0x1;
        } else {
            *(outbuf[j]++) = s->tls_version & 0xff;
        }

        /* field where we are to write out packet length */
        plen[j] = outbuf[j];
        outbuf[j] += 2;

        /* lets setup the record stuff. */
        TLS_RECORD_set_data(&wr[j], outbuf[j] + eivlen);
        TLS_RECORD_set_length(&wr[j], (int)pipelens[j]);
        TLS_RECORD_set_input(&wr[j], (fc_u8 *)&buf[totlen]);
        totlen += pipelens[j];

        /*
         * we now 'read' from wr->input, wr->length bytes into wr->data
         */

        memcpy(wr[j].rd_data, wr[j].rd_input, wr[j].rd_length);
        TLS_RECORD_reset_input(&wr[j]);

        /*
         * we should still have the output to wr->data and the input from
         * wr->input.  Length should be wr->length. wr->data still points in the
         * wb->buf
         */

#if 0
        if (!TLS_WRITE_ETM(s) && mac_size != 0) {
            if (s->method->ssl3_enc->mac(s, &wr[j],
                                         &(outbuf[j][wr[j].length + eivlen]),
                                         1) < 0)
                goto err;
            TLS_RECORD_add_length(&wr[j], mac_size);
        }
#endif

        TLS_RECORD_set_data(&wr[j], outbuf[j]);
        TLS_RECORD_reset_input(&wr[j]);

        if (eivlen) {
            /*
             * if (RAND_pseudo_bytes(p, eivlen) <= 0) goto err;
             */
            TLS_RECORD_add_length(&wr[j], eivlen);
        }
    }

    if (s->tls_method->md_enc->em_enc(s, wr, numpipes, 1) < 1) {
        goto err;
    }

    for (j = 0; j < numpipes; j++) {
#if 0
        if (TLS_WRITE_ETM(s) && mac_size != 0) {
            if (s->method->ssl3_enc->mac(s, &wr[j],
                                         outbuf[j] + wr[j].length, 1) < 0)
                goto err;
            TLS_RECORD_add_length(&wr[j], mac_size);
        }
#endif

        /* record length after mac and block padding */
        s2n(TLS_RECORD_get_length(&wr[j]), plen[j]);

        /*
         * we should now have wr->data pointing to the encrypted data, which is
         * wr->length long
         */
        TLS_RECORD_set_type(&wr[j], type); /* not needed but helps for
                                             * debugging */
        TLS_RECORD_add_length(&wr[j], TLS1_RT_HEADER_LENGTH);

        if (create_empty_fragment) {
            /*
             * we are in a recursive call; just return the length, don't write
             * out anything here
             */
            if (j > 0) {
                /* We should never be pipelining an empty fragment!! */
                goto err;
            }
            return TLS_RECORD_get_length(wr);
        }

        /* now let's set up wb */
        TLS_BUFFER_set_left(&s->tls_rlayer.rl_wbuf[j], 
                prefix_len + TLS_RECORD_get_length(&wr[j]));
    }

    /*
     * memorize arguments so that ssl3_write_pending can detect bad write
     * retries later
     */
    s->tls_rlayer.rl_wpend_tot = totlen;
    s->tls_rlayer.rl_wpend_buf = buf;
    s->tls_rlayer.rl_wpend_type = type;
    s->tls_rlayer.rl_wpend_ret = totlen;

    /* we now just need to write the buffer */
    return tls1_2_write_pending(s, type, buf, totlen);
 err:
    return -1;
}

int
tls1_2_write_bytes(TLS *s, int type, const void *buf, int len)
{
    const fc_u8     *b = buf;
    RECORD_LAYER    *rl = &s->tls_rlayer;
    TLS_BUFFER      *wb = &rl->rl_wbuf[0];
    fc_u32          n = 0;
    fc_u32          split_send_fragment = 0;
    fc_u32          max_send_fragment = 0;
    fc_u32          maxpipes = 0;
    int             tot = 0;
    int             i = 0;

    if (len < 0) {
        FC_LOG("error\n");
        return -1;
    }

    s->tls_rwstate = TLS_NOTHING;
    tot = rl->rl_wnum;

    if (wb->bf_left != 0) {
        i = tls1_2_write_pending(s, type, &b[tot], rl->rl_wpend_tot);
        if (i <= 0) {
            rl->rl_wnum = tot;
            FC_LOG("error\n");
            return -1;
        } 
        tot += i;               /* this might be last fragment */
    }

    if (tot == len) {
        FC_LOG("return tot = %d\n", tot);
        return tot;
    }

    n = (len - tot);

    split_send_fragment = s->tls_split_send_fragment;
    max_send_fragment = s->tls_max_send_fragment;
    maxpipes = s->tls_max_pipelines;
    if (maxpipes > FC_TLS_MAX_PIPELINES) {
        FC_LOG("error\n");
        return -1;
    }

    if (maxpipes == 0) {
        maxpipes = 1;
    }

    if (max_send_fragment == 0 || split_send_fragment > max_send_fragment ||
            split_send_fragment == 0) {
        FC_LOG("error\n");
        return -1;
    }

    while (1) {
        fc_u32      pipelens[FC_TLS_MAX_PIPELINES] = {};
        fc_u32      tmppipelen = 0;
        fc_u32      remain = 0;
        fc_u32      numpipes = 0;
        fc_u32      j = 0;

        if (n == 0) {
            numpipes = 1;
        } else {
            numpipes = ((n - 1)/split_send_fragment) + 1;
        }

        if (numpipes > maxpipes) {
            numpipes = maxpipes;
        }

        tmppipelen = n/numpipes;
        if (tmppipelen >= max_send_fragment) {
            /*
             * We have enough data to completely fill all available
             * pipelines
             */
            for (j = 0; j < numpipes; j++) {
                pipelens[j] = max_send_fragment;
            }
        } else {
            /* We can partially fill all available pipelines */
            remain = n % numpipes;
            for (j = 0; j < numpipes; j++) {
                pipelens[j] = tmppipelen;
                if (j < remain) {
                    pipelens[j]++;
                }
            }
        }

        i = do_tls1_2_write(s, type, &(b[tot]), pipelens, numpipes, 0);
        if (i <= 0) {
            s->tls_rlayer.rl_wnum = tot;
            return i;
        }

        if ((i == (int)n) /*||
                (type == TLS3_RT_APPLICATION_DATA &&
                 (s->mode & TLS_MODE_ENABLE_PARTIAL_WRITE))*/) {
            /*
             * next chunk of data should get another prepended empty fragment
             * in ciphersuites with known-IV weakness:
             */
            //s->s3->empty_fragment_done = 0;

            return tot + i;
        }

        n -= i;
        tot += i;
    }

    return 0;
}


