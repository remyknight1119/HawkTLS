#include <string.h>

#include <falcontls/tls.h>
#include <falcontls/bio.h>
#include <fc_log.h>

#include "statem.h"
#include "tls_locl.h"
#include "tls1_2.h"
#include "record_locl.h"

int
tls1_2_read_bytes(TLS *s, int type, int *recvd_type, fc_u8 *buf,
        int len, int peek)
{
    return 0;
}

static int 
tls1_2_write_pending(TLS *s, int type, const fc_u8 *buf, fc_u32 len)
{
    TLS_BUFFER      *wb = s->tls_rlayer.rl_wbuf;
    fc_u32          currbuf = 0;
    int             i = 0;

    FC_LOG("in\n");
    if ((s->tls_rlayer.rl_wpend_tot > (int)len)
        || ((s->tls_rlayer.rl_wpend_buf != buf)/* &&
            !(s->mode & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)*/)
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
#if 0
            if (SSL_IS_DTLS(s)) {
                /*
                 * For DTLS, just drop it. That's kind of the whole point in
                 * using a datagram service
                 */
                TLS_BUFFER_set_left(&wb[currbuf], 0);
            }
#endif
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
        TLS_RECORD_add_length(&wr[j], TLS_RT_HEADER_LENGTH);

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


