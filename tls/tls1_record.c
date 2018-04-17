#include <string.h>

#include <falcontls/tls.h>
#include <falcontls/evp.h>
#include <fc_assert.h>
#include <fc_log.h>

#include "statem.h"
#include "tls_locl.h"
#include "tls1.h"
#include "tls1_2.h"
#include "record_locl.h"
#include "alert.h"

int
tls1_read_n(TLS *s, int n, int max, int extend, int clearold)
{
    return 0;
}

/*
 * Peeks ahead into "read_ahead" data to see if we have a whole record waiting
 * for us in the buffer.
 */
static int 
tls1_record_app_data_waiting(TLS *s)
{
    TLS_BUFFER      *rbuf = NULL;
    int             left = 0;
    int             len = 0;
    fc_u8           *p = NULL;

    rbuf = RECORD_LAYER_get_rbuf(&s->tls_rlayer);

    p = TLS_BUFFER_get_buf(rbuf);
    if (p == NULL) {
        return 0;
    }

    left = TLS_BUFFER_get_left(rbuf);

    if (left < TLS1_RT_HEADER_LENGTH) {
        return 0;
    }

    p += TLS_BUFFER_get_offset(rbuf);

    /*
     * We only check the type and record length, we will sanity check version
     * etc later
     */
    if (*p != TLS_RT_APPLICATION_DATA) {
        return 0;
    }

    p += 3;
    n2s(p, len);

    if (left < TLS1_RT_HEADER_LENGTH + len) {
        return 0;
    }

    return 1;
}


/*
 * MAX_EMPTY_RECORDS defines the number of consecutive, empty records that
 * will be processed per call to tls1_get_record. Without this limit an
 * attacker could send empty records at a faster rate than we can process and
 * cause tls1_get_record to loop forever.
 */
#define MAX_EMPTY_RECORDS 32

int
tls1_get_record(TLS *s)
{
    RECORD_LAYER    *rl = NULL;
    TLS_RECORD      *rr = NULL;
    TLS_BUFFER      *rbuf = NULL;
    TLS_SESSION     *sess = NULL;
    fc_u8           *p = NULL;
    fc_u8           md[FC_EVP_MAX_MD_SIZE];
    fc_u32          num_recs = 0;
    fc_u32          max_recs = 0;
    fc_u32          j = 0;
    short           version = 0;
    unsigned        mac_size = 0;
    int             tls_major = 0;
    int             tls_minor = 0;
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
             < TLS1_RT_HEADER_LENGTH)) {
            n = tls1_read_n(s, TLS1_RT_HEADER_LENGTH,
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
                al = TLS_AD_HANDSHAKE_FAILURE;
                goto f_err;
            }
            /* SSLv3+ style record */
            /* Pull apart the header into the TLS_RECORD */
            rr[num_recs].rd_type = *(p++);
            tls_major = *(p++);
            tls_minor = *(p++);
            version = (tls_major << 8) | tls_minor;
            rr[num_recs].rd_rec_version = version;
            n2s(p, rr[num_recs].rd_length);

            /* Lets check version */
            if (!s->tls_first_packet && version != s->tls_version) {
                al = TLS_AD_PROTOCOL_VERSION;
                goto f_err;
            }

            if ((version >> 8) != TLS_VERSION_MAJOR) {
                al = TLS_AD_PROTOCOL_VERSION;
                goto f_err;
            }

            if (rr[num_recs].rd_length >
                    TLS_BUFFER_get_len(rbuf) - TLS1_RT_HEADER_LENGTH) {
                al = TLS_AD_RECORD_OVERFLOW;
                goto f_err;
            }

            /* now s->rlayer.rstate == TLS_ST_READ_BODY */
        }

        /*
         * s->rlayer.rstate == TLS_ST_READ_BODY, get and decode the data.
         * Calculate how much more data we need to read for the rest of the
         * record
         */
        i = rr[num_recs].rd_length;
        if (i > 0) {
            /* now s->packet_length == TLS1_RT_HEADER_LENGTH */
            n = tls1_read_n(s, i, i, 1, 0);
            if (n <= 0) {
                return (n);     /* error or non-blocking io */
            }
        }

        /* set state for later operations */
        RECORD_LAYER_set_rstate(rl, TLS_ST_READ_HEADER);

        /*
         * At this point, s->packet_length == TLS1_RT_HEADER_LENGTH + rr->length,
         * or s->packet_length == SSL2_RT_HEADER_LENGTH + rr->length
         * and we have that many bytes in s->packet
         */
        rr[num_recs].rd_input =
            &(RECORD_LAYER_get_packet(rl)[TLS1_RT_HEADER_LENGTH]);

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
        if (rr[num_recs].rd_length > TLS1_RT_MAX_ENCRYPTED_LENGTH) {
            al = TLS_AD_RECORD_OVERFLOW;
            goto f_err;
        }

        /* decrypt in place in 'rr->input' */
        rr[num_recs].rd_data = rr[num_recs].rd_input;
        rr[num_recs].rd_orig_len = rr[num_recs].rd_length;

        /* Mark this record as not read by upper layers yet */
        rr[num_recs].rd_read = 0;

        num_recs++;

        /* we have pulled in a full packet so zero things */
        RECORD_LAYER_reset_packet_length(rl);
        RECORD_LAYER_clear_first_record(rl);
    } while (num_recs < max_recs
             && rr[num_recs - 1].rd_type == TLS_RT_APPLICATION_DATA
             && TLS_USE_EXPLICIT_IV(s)
             && s->tls_enc_read_ctx != NULL
             &&
             (FC_EVP_CIPHER_flags(FC_EVP_CIPHER_CTX_cipher(s->tls_enc_read_ctx))
                 & FC_EVP_CIPH_FLAG_PIPELINE)
             && tls1_record_app_data_waiting(s));

    enc_err = s->tls_method->md_enc->em_enc(s, rr, num_recs, 0);
    /*-
     * enc_err is:
     *    0: (in non-constant time) if the record is publically invalid.
     *    1: if the padding is valid
     *    -1: if the padding is invalid
     */
    if (enc_err == 0) {
        al = TLS_AD_DECRYPTION_FAILED;
        goto f_err;
    }

    /* r->length is now the compressed data plus mac */
    if ((sess != NULL) &&
        (s->tls_enc_read_ctx != NULL) &&
        FC_EVP_MD_CTX_md(s->tls_read_hash) != NULL) {
        /* s->read_hash != NULL => mac_size != -1 */
        fc_u8   *mac = NULL;

        mac_size = FC_EVP_MD_CTX_size(s->tls_read_hash);
        fc_assert(mac_size <= FC_EVP_MAX_MD_SIZE);

        for (j = 0; j < num_recs; j++) {
            /*
             * In this case there's no padding, so |rec->orig_len| equals
             * |rec->length| and we checked that there's enough bytes for
             * |mac_size| above.
             */
            rr[j].rd_length -= mac_size;
            mac = &rr[j].rd_data[rr[j].rd_length];

            i = s->tls_method->md_enc->em_mac(s, &rr[j], md, 0 /* not send */ );
            if (i < 0 || mac == NULL
                || memcmp(md, mac, (size_t)mac_size) != 0) {
                enc_err = -1;
            }
            if (rr->rd_length > TLS1_RT_MAX_PLAIN_LENGTH + mac_size) {
                enc_err = -1;
            }
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
        al = TLS_AD_BAD_RECORD_MAC;
        goto f_err;
    }

    for (j = 0; j < num_recs; j++) {
        if (rr[j].rd_length > TLS1_RT_MAX_PLAIN_LENGTH) {
            al = TLS_AD_RECORD_OVERFLOW;
            goto f_err;
        }

        rr[j].rd_off = 0;
        /*-
         * So at this point the following is true
         * rr[j].rd_type   is the type of record
         * rr[j].rd_length == number of bytes in record
         * rr[j].rd_off    == offset to first valid byte
         * rr[j].rd_data   == where to take bytes from, increment after use :-).
         */

        /* just read a 0 length packet */
        if (rr[j].rd_length == 0) {
            RECORD_LAYER_inc_empty_record_count(rl);
            if (RECORD_LAYER_get_empty_record_count(rl)
                > MAX_EMPTY_RECORDS) {
                al = TLS_AD_UNEXPECTED_MESSAGE;
                goto f_err;
            }
        } else {
            RECORD_LAYER_reset_empty_record_count(rl);
        }
    }

    RECORD_LAYER_set_numrpipes(rl, num_recs);
    return 1;

 f_err:
    tls_send_alert(s, TLS_AL_FATAL, al);
    return ret;
}
