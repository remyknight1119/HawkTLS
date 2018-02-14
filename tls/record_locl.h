#ifndef __FC_RECORD_LOCL_H__
#define __FC_RECORD_LOCL_H__

#include <falcontls/types.h>
#include <falcontls/tls.h>

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
    TLS_BUFFER      rl_rbuf;
    TLS_BUFFER      rl_wbuf[FC_TLS_MAX_PIPELINES];
    TLS_RECORD      rl_rrec[FC_TLS_MAX_PIPELINES];
    fc_u32          rl_numwpipes;
    /* number of bytes sent so far */
    fc_u32          rl_wnum;
    /* number bytes written */
    int             rl_wpend_tot;
} RECORD_LAYER;

int tls_setup_buffers(TLS *s);
int tls1_2_read_bytes(TLS *s, int type, int *recvd_type,
        unsigned char *buf, int len, int peek);
int tls1_2_write_bytes(TLS *s, int type, const void *buf, int len);

#endif
