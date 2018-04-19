#ifndef __FC_RECORD_LOCL_H__
#define __FC_RECORD_LOCL_H__

#include <falcontls/types.h>
#include <falcontls/tls.h>

#define MAX_WARN_ALERT_COUNT    5

#define RECORD_LAYER_get_rbuf(rl)               (&(rl)->rl_rbuf)
#define RECORD_LAYER_get_wbuf(rl)               ((rl)->rl_wbuf)
#define RECORD_LAYER_get_rrec(rl)               ((rl)->rl_rrec)
#define RECORD_LAYER_set_packet(rl, p)          ((rl)->rl_packet = (p))
#define RECORD_LAYER_reset_packet_length(rl)    ((rl)->rl_packet_length = 0)
#define RECORD_LAYER_get_rstate(rl)             ((rl)->rl_rstate)
#define RECORD_LAYER_set_rstate(rl, st)         ((rl)->rl_rstate = (st))
#define RECORD_LAYER_get_read_sequence(rl)      ((rl)->rl_read_sequence)
#define RECORD_LAYER_get_write_sequence(rl)     ((rl)->rl_write_sequence)
#define RECORD_LAYER_get_numrpipes(rl)          ((rl)->rl_numrpipes)
#define RECORD_LAYER_set_numrpipes(rl, n)       ((rl)->rl_numrpipes = (n))
#define RECORD_LAYER_inc_empty_record_count(rl) ((rl)->rl_empty_record_count++)
#define RECORD_LAYER_reset_empty_record_count(rl) \
                                                ((rl)->rl_empty_record_count = 0)
#define RECORD_LAYER_get_empty_record_count(rl) ((rl)->rl_empty_record_count)
#define RECORD_LAYER_is_first_record(rl)        ((rl)->rl_is_first_record)
#define RECORD_LAYER_set_first_record(rl)       ((rl)->rl_is_first_record = 1)
#define RECORD_LAYER_clear_first_record(rl)     ((rl)->rl_is_first_record = 0)

#define RECORD_LAYER_set_read_ahead(rl, ra)     ((rl)->rl_read_ahead = (ra))
#define RECORD_LAYER_get_read_ahead(rl)         ((rl)->rl_read_ahead)
#define RECORD_LAYER_get_packet(rl)             ((rl)->rl_packet)
#define RECORD_LAYER_get_packet_length(rl)      ((rl)->rl_packet_length)
#define RECORD_LAYER_add_packet_length(rl, inc) ((rl)->rl_packet_length += (inc))

#define TLS_BUFFER_get_left(b)              ((b)->bf_left)
#define TLS_BUFFER_set_left(b, l)           ((b)->bf_left = (l))
#define TLS_BUFFER_add_left(b, l)           ((b)->bf_left += (l))
#define TLS_BUFFER_get_buf(b)               ((b)->bf_buf)
#define TLS_BUFFER_set_buf(b, n)            ((b)->bf_buf = (n))
#define TLS_BUFFER_get_len(b)               ((b)->bf_len)
#define TLS_BUFFER_get_offset(b)            ((b)->bf_offset)
#define TLS_BUFFER_set_offset(b, o)         ((b)->bf_offset = (o))
#define TLS_BUFFER_add_offset(b, o)         ((b)->bf_offset += (o))
#define TLS_BUFFER_is_initialised(b)        ((b)->bf_buf != NULL)

typedef struct tls_buffer_t {
    /* at least TLS_RT_MAX_PACKET_SIZE bytes, see tls_setup_buffers() */
    fc_u8   *bf_buf;
    /* default buffer size (or 0 if no default set) */
    size_t  bf_default_len;
    /* buffer size */
    size_t  bf_len;
    /* where to 'copy from' */
    int     bf_offset;
    /* how many bytes left */
    int     bf_left;
} TLS_BUFFER;

#define SEQ_NUM_SIZE                        8

typedef struct tls_record_t {
    /* Record layer version */
    /* r */
    int         rd_rec_version;
    /* type of record */
    /* r */
    int         rd_type;
    /* How many bytes available */
    /* rw */
    fc_u32      rd_length;
    /*
     * How many bytes were available before padding was removed? This is used
     * to implement the MAC check in constant time for CBC records.
     */
    /* rw */
    fc_u32      rd_orig_len;
    /* read/write offset into 'buf' */
    /* r */
    fc_u32      rd_off;
    /* pointer to the record data */
    /* rw */
    fc_u8       *rd_data;
    /* where the decode bytes are */
    /* rw */
    fc_u8       *rd_input;
    /* only used with decompression - malloc()ed */
    /* r */
    fc_u8       *rd_comp;
    /* Whether the data from this record has already been read or not */
    /* r */
    fc_u32      rd_read;
    /* epoch number, needed by DTLS1 */
    /* r */
    fc_ulong    rd_epoch;
    /* sequence number, needed by DTLS1 */
    /* r */
    fc_u8       rd_seq_num[SEQ_NUM_SIZE];
} TLS_RECORD;


typedef struct record_layer_t {
    TLS             *rl_tls;
    fc_u8           *rl_packet;
    const fc_u8     *rl_wpend_buf;
    TLS_BUFFER      rl_rbuf;
    TLS_BUFFER      rl_wbuf[FC_TLS_MAX_PIPELINES];
    /* each decoded record goes in here */
    TLS_RECORD      rl_rrec[FC_TLS_MAX_PIPELINES];
    fc_u32          rl_numrpipes;
    fc_u32          rl_numwpipes;
    fc_u32          rl_packet_length;
    /* number of bytes sent so far */
    fc_u32          rl_wnum;
    fc_u8           rl_alert_fragment[2];
    fc_u32          rl_alert_fragment_len;
    /* Count of the number of consecutive warning alerts received */
    fc_u32          rl_alert_count;
    fc_u8           rl_handshake_fragment[4];
    fc_u32          rl_handshake_fragment_len;
    fc_u32          rl_is_first_record;
    /* The number of consecutive empty records we have received */
    fc_u32          rl_empty_record_count;
    int             rl_rstate;
    /*
     * Read as many input bytes as possible (for
     * non-blocking reads)
     */
    int             rl_read_ahead;
    /* number bytes written */
    int             rl_wpend_tot;
    int             rl_wpend_type;
    int             rl_wpend_ret;
} RECORD_LAYER;

#define TLS_RECORD_get_type(r)                 ((r)->rd_type)
#define TLS_RECORD_set_type(r, t)              ((r)->rd_type = (t))
#define TLS_RECORD_get_length(r)               ((r)->rd_length)
#define TLS_RECORD_set_length(r, l)            ((r)->rd_length = (l))
#define TLS_RECORD_add_length(r, l)            ((r)->rd_length += (l))
#define TLS_RECORD_sub_length(r, l)            ((r)->rd_length -= (l))
#define TLS_RECORD_get_data(r)                 ((r)->rd_data)
#define TLS_RECORD_set_data(r, d)              ((r)->rd_data = (d))
#define TLS_RECORD_get_input(r)                ((r)->rd_input)
#define TLS_RECORD_set_input(r, i)             ((r)->rd_input = (i))
#define TLS_RECORD_reset_input(r)              ((r)->rd_input = (r)->rd_data)
#define TLS_RECORD_get_seq_num(r)              ((r)->rd_seq_num)
#define TLS_RECORD_get_off(r)                  ((r)->rd_off)
#define TLS_RECORD_set_off(r, o)               ((r)->rd_off = (o))
#define TLS_RECORD_add_off(r, o)               ((r)->rd_off += (o))
#define TLS_RECORD_get_epoch(r)                ((r)->rd_epoch)
#define TLS_RECORD_is_read(r)                  ((r)->rd_read)
#define TLS_RECORD_set_read(r)                 ((r)->rd_read = 1)


int tls_setup_buffers(TLS *s);
int tls1_2_read_bytes(TLS *s, int type, int *recvd_type,
        fc_u8 *buf, int len, int peek);
int tls1_2_write_bytes(TLS *s, int type, const void *buf, int len);
int tls_setup_read_buffer(TLS *s);
int tls_setup_write_buffer(TLS *s, fc_u32 numwpipes, size_t len);
int tls_release_write_buffer(TLS *s);
int tls_release_read_buffer(TLS *s);
int RECORD_LAYER_write_pending(const RECORD_LAYER *rl);
int tls1_get_record(TLS *s);

#endif
