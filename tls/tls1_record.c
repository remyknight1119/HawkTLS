
#include <falcontls/tls.h>
#include <fc_log.h>

#include "statem.h"
#include "tls_locl.h"
#include "tls1_2.h"
#include "record_locl.h"
#include "alert.h"

int
tls1_read_n(TLS *s, int n, int max, int extend, int clearold)
{
    return 0;
}

int
tls1_get_record(TLS *s)
{
    RECORD_LAYER    *rl = NULL;
    TLS_RECORD      *rr = NULL;
    TLS_BUFFER      *rbuf = NULL;
    TLS_SESSION     *sess = NULL;
    fc_u8           *p = NULL;
    fc_u8           md[EVP_MAX_MD_SIZE];
    fc_u32          num_recs = 0;
    fc_u32          max_recs = 0;
    fc_u32          j = 0;
    short           version = 0;
    unsigned        mac_size = 0;
    int             imac_size = 0;
    int             ssl_major = 0;
    int             ssl_minor = 0;
    int             al = 0;;
    int             enc_err = 0;
    int             n = 0;
    int             i = 0;
    int             ret = -1;

    rl = &s->tls_rlayer;
    rr = RECORD_LAYER_get_rrec(rl);
    rbuf = RECORD_LAYER_get_rbuf(rl);
    max_recs = s->tls_max_pipelines;
    if (max_recs == 0) {
        max_recs = 1;
    }
    sess = s->tls_session;

    do {
        /* check if we have the header */
        if ((RECORD_LAYER_get_rstate(rl) != TLS_ST_READ_BODY) ||
            (RECORD_LAYER_get_packet_length(rl)
             < TLS_RT_HEADER_LENGTH)) {
            n = tls1_read_n(s, TLS_RT_HEADER_LENGTH,
                            TLS_BUFFER_get_len(rbuf), 0,
                            num_recs == 0 ? 1 : 0);
            if (n <= 0) {
                return (n);     /* error or non-blocking */
            }
            RECORD_LAYER_set_rstate(rl, TLS_ST_READ_BODY);

            p = RECORD_LAYER_get_packet(rl);

            /*
             * The first record received by the server may be a V2ClientHello.
             */
            if (s->tls_server && RECORD_LAYER_is_first_record(rl)
                && (p[0] & 0x80) && (p[2] == TLS1_MT_CLIENT_HELLO)) {
                al = SSL_AD_HANDSHAKE_FAILURE;
                goto f_err;
            } else {
                /* SSLv3+ style record */
                /* Pull apart the header into the TLS_RECORD */
                rr[num_recs].type = *(p++);
                ssl_major = *(p++);
                ssl_minor = *(p++);
                version = (ssl_major << 8) | ssl_minor;
                rr[num_recs].rec_version = version;
                n2s(p, rr[num_recs].length);

                /* Lets check version */
                if (!s->first_packet && version != s->version) {
                    if ((s->version & 0xFF00) == (version & 0xFF00)
                        && !s->enc_write_ctx && !s->write_hash) {
                        if (rr->type == TLS_RT_ALERT) {
                            /*
                             * The record is using an incorrect version number,
                             * but what we've got appears to be an alert. We
                             * haven't read the body yet to check whether its a
                             * fatal or not - but chances are it is. We probably
                             * shouldn't send a fatal alert back. We'll just
                             * end.
                             */
                            goto err;
                        }
                        /*
                         * Send back error using their minor version number :-)
                         */
                        s->tls_version = (unsigned short)version;
                    }
                    al = TLS_AD_PROTOCOL_VERSION;
                    goto f_err;
                }

                if ((version >> 8) != TLS_VERSION_MAJOR) {
                    if (RECORD_LAYER_is_first_record(&s->rlayer)) {
                        /* Go back to start of packet, look at the five bytes
                         * that we have. */
                        p = RECORD_LAYER_get_packet(&s->rlayer);
                        if (strncmp((char *)p, "GET ", 4) == 0 ||
                            strncmp((char *)p, "POST ", 5) == 0 ||
                            strncmp((char *)p, "HEAD ", 5) == 0 ||
                            strncmp((char *)p, "PUT ", 4) == 0) {
                            SSLerr(SSL_F_TLS_GET_RECORD, SSL_R_HTTP_REQUEST);
                            goto err;
                        } else if (strncmp((char *)p, "CONNE", 5) == 0) {
                            SSLerr(SSL_F_TLS_GET_RECORD,
                                   SSL_R_HTTPS_PROXY_REQUEST);
                            goto err;
                        }

                        /* Doesn't look like TLS - don't send an alert */
                        goto err;
                    } 
                    al = SSL_AD_PROTOCOL_VERSION;
                    goto f_err;
                }

                if (rr[num_recs].length >
                    TLS_BUFFER_get_len(rbuf) - TLS_RT_HEADER_LENGTH) {
                    al = SSL_AD_RECORD_OVERFLOW;
                    goto f_err;
                }
            }

            /* now s->rlayer.rstate == SSL_ST_READ_BODY */
        }

        /*
         * s->rlayer.rstate == SSL_ST_READ_BODY, get and decode the data.
         * Calculate how much more data we need to read for the rest of the
         * record
         */
        i = rr[num_recs].length;
        if (i > 0) {
            /* now s->packet_length == TLS_RT_HEADER_LENGTH */
            n = tls1_read_n(s, i, i, 1, 0);
            if (n <= 0) {
                return (n);     /* error or non-blocking io */
            }
        }

        /* set state for later operations */
        RECORD_LAYER_set_rstate(&s->rlayer, TLS_ST_READ_HEADER);

        /*
         * At this point, s->packet_length == TLS_RT_HEADER_LENGTH + rr->length,
         * or s->packet_length == SSL2_RT_HEADER_LENGTH + rr->length
         * and we have that many bytes in s->packet
         */
        rr[num_recs].input =
            &(RECORD_LAYER_get_packet(&s->rlayer)[TLS_RT_HEADER_LENGTH]);

        /*
         * ok, we can now read from 's->packet' data into 'rr' rr->input points
         * at rr->length bytes, which need to be copied into rr->data by either
         * the decryption or by the decompression When the data is 'copied' into
         * the rr->data buffer, rr->input will be pointed at the new buffer
         */

        /*
         * We now have - encrypted [ MAC [ compressed [ plain ] ] ] rr->length
         * bytes of encrypted compressed stuff.
         */

        /* check is not needed I believe */
        if (rr[num_recs].length > TLS_RT_MAX_ENCRYPTED_LENGTH) {
            al = SSL_AD_RECORD_OVERFLOW;
            goto f_err;
        }

        /* decrypt in place in 'rr->input' */
        rr[num_recs].data = rr[num_recs].input;
        rr[num_recs].orig_len = rr[num_recs].length;

        /* Mark this record as not read by upper layers yet */
        rr[num_recs].read = 0;

        num_recs++;

        /* we have pulled in a full packet so zero things */
        RECORD_LAYER_reset_packet_length(&s->rlayer);
        RECORD_LAYER_clear_first_record(&s->rlayer);
    } while (num_recs < max_recs
             && rr[num_recs - 1].type == TLS_RT_APPLICATION_DATA
             && SSL_USE_EXPLICIT_IV(s)
             && s->enc_read_ctx != NULL
             && (EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(s->enc_read_ctx))
                 & EVP_CIPH_FLAG_PIPELINE)
             && ssl3_record_app_data_waiting(s));

    /*
     * If in encrypt-then-mac mode calculate mac from encrypted record. All
     * the details below are public so no timing details can leak.
     */
    if (SSL_READ_ETM(s) && s->read_hash) {
        fc_u8 *mac;

        imac_size = EVP_MD_CTX_size(s->read_hash);
        assert(imac_size >= 0 && imac_size <= EVP_MAX_MD_SIZE);
        if (imac_size < 0 || imac_size > EVP_MAX_MD_SIZE) {
                al = SSL_AD_INTERNAL_ERROR;
                SSLerr(SSL_F_TLS_GET_RECORD, ERR_LIB_EVP);
                goto f_err;
        }
        mac_size = (unsigned)imac_size;

        for (j = 0; j < num_recs; j++) {
            if (rr[j].length < mac_size) {
                al = SSL_AD_DECODE_ERROR;
                SSLerr(SSL_F_TLS_GET_RECORD, SSL_R_LENGTH_TOO_SHORT);
                goto f_err;
            }
            rr[j].length -= mac_size;
            mac = rr[j].data + rr[j].length;
            i = s->method->ssl3_enc->mac(s, &rr[j], md, 0 /* not send */ );
            if (i < 0 || CRYPTO_memcmp(md, mac, (size_t)mac_size) != 0) {
                al = SSL_AD_BAD_RECORD_MAC;
                SSLerr(SSL_F_TLS_GET_RECORD,
                       SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
                goto f_err;
            }
        }
    }

    enc_err = s->method->ssl3_enc->enc(s, rr, num_recs, 0);
    /*-
     * enc_err is:
     *    0: (in non-constant time) if the record is publically invalid.
     *    1: if the padding is valid
     *    -1: if the padding is invalid
     */
    if (enc_err == 0) {
        al = SSL_AD_DECRYPTION_FAILED;
        goto f_err;
    }
#ifdef SSL_DEBUG
    printf("dec %d\n", rr->length);
    {
        fc_u32 z;
        for (z = 0; z < rr->length; z++)
            printf("%02X%c", rr->data[z], ((z + 1) % 16) ? ' ' : '\n');
    }
    printf("\n");
#endif

    /* r->length is now the compressed data plus mac */
    if ((sess != NULL) &&
        (s->enc_read_ctx != NULL) &&
        (!SSL_READ_ETM(s) && EVP_MD_CTX_md(s->read_hash) != NULL)) {
        /* s->read_hash != NULL => mac_size != -1 */
        fc_u8 *mac = NULL;
        fc_u8 mac_tmp[EVP_MAX_MD_SIZE];

        mac_size = EVP_MD_CTX_size(s->read_hash);
        OPENSSL_assert(mac_size <= EVP_MAX_MD_SIZE);

        for (j = 0; j < num_recs; j++) {
            /*
             * orig_len is the length of the record before any padding was
             * removed. This is public information, as is the MAC in use,
             * therefore we can safely process the record in a different amount
             * of time if it's too short to possibly contain a MAC.
             */
            if (rr[j].orig_len < mac_size ||
                /* CBC records must have a padding length byte too. */
                (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
                 rr[j].orig_len < mac_size + 1)) {
                al = SSL_AD_DECODE_ERROR;
                SSLerr(SSL_F_TLS_GET_RECORD, SSL_R_LENGTH_TOO_SHORT);
                goto f_err;
            }

            if (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE) {
                /*
                 * We update the length so that the TLS header bytes can be
                 * constructed correctly but we need to extract the MAC in
                 * constant time from within the record, without leaking the
                 * contents of the padding bytes.
                 */
                mac = mac_tmp;
                ssl3_cbc_copy_mac(mac_tmp, &rr[j], mac_size);
                rr[j].length -= mac_size;
            } else {
                /*
                 * In this case there's no padding, so |rec->orig_len| equals
                 * |rec->length| and we checked that there's enough bytes for
                 * |mac_size| above.
                 */
                rr[j].length -= mac_size;
                mac = &rr[j].data[rr[j].length];
            }

            i = s->method->ssl3_enc->mac(s, &rr[j], md, 0 /* not send */ );
            if (i < 0 || mac == NULL
                || CRYPTO_memcmp(md, mac, (size_t)mac_size) != 0)
                enc_err = -1;
            if (rr->length > TLS_RT_MAX_COMPRESSED_LENGTH + mac_size)
                enc_err = -1;
        }
    }

    if (enc_err < 0) {
        /*
         * A separate 'decryption_failed' alert was introduced with TLS 1.0,
         * SSL 3.0 only has 'bad_record_mac'.  But unless a decryption
         * failure is directly visible from the ciphertext anyway, we should
         * not reveal which kind of error occurred -- this might become
         * visible to an attacker (e.g. via a logfile)
         */
        al = SSL_AD_BAD_RECORD_MAC;
        SSLerr(SSL_F_TLS_GET_RECORD,
               SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
        goto f_err;
    }

    for (j = 0; j < num_recs; j++) {
        /* rr[j].length is now just compressed */
        if (s->expand != NULL) {
            if (rr[j].length > TLS_RT_MAX_COMPRESSED_LENGTH) {
                al = SSL_AD_RECORD_OVERFLOW;
                SSLerr(SSL_F_TLS_GET_RECORD, SSL_R_COMPRESSED_LENGTH_TOO_LONG);
                goto f_err;
            }
            if (!ssl3_do_uncompress(s, &rr[j])) {
                al = SSL_AD_DECOMPRESSION_FAILURE;
                goto f_err;
            }
        }

        if (rr[j].length > TLS_RT_MAX_PLAIN_LENGTH) {
            al = SSL_AD_RECORD_OVERFLOW;
            goto f_err;
        }

        rr[j].off = 0;
        /*-
         * So at this point the following is true
         * rr[j].type   is the type of record
         * rr[j].length == number of bytes in record
         * rr[j].off    == offset to first valid byte
         * rr[j].data   == where to take bytes from, increment after use :-).
         */

        /* just read a 0 length packet */
        if (rr[j].length == 0) {
            RECORD_LAYER_inc_empty_record_count(&s->rlayer);
            if (RECORD_LAYER_get_empty_record_count(&s->rlayer)
                > MAX_EMPTY_RECORDS) {
                al = SSL_AD_UNEXPECTED_MESSAGE;
                goto f_err;
            }
        } else {
            RECORD_LAYER_reset_empty_record_count(&s->rlayer);
        }
    }

    RECORD_LAYER_set_numrpipes(&s->rlayer, num_recs);
    return 1;

 f_err:
    tls_send_alert(s, TLS_AL_FATAL, al);
 err:
    return ret;
}
