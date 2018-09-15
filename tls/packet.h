#ifndef __FC_PACKET_H__
#define __FC_PACKET_H__

#include <string.h>

#include <falcontls/types.h>

typedef struct {
    /* Pointer to where we are currently reading from */
    const fc_u8     *pk_curr;
    /* Number of bytes remaining */
    size_t          pk_remaining;
} PACKET;

/* Internal unchecked shorthand; don't use outside this file. */
static inline void packet_forward(PACKET *pkt, size_t len)
{
    pkt->pk_curr += len;
    pkt->pk_remaining -= len;
}

/*
 * Returns the number of bytes remaining to be read in the PACKET
 */
static inline size_t PACKET_remaining(const PACKET *pkt)
{
    return pkt->pk_remaining;
}

/*
 * Returns a pointer to the first byte after the packet data.
 * Useful for integrating with non-PACKET parsing code.
 * Specifically, we use PACKET_end() to verify that a d2i_... call
 * has consumed the entire packet contents.
 */
static inline const fc_u8 *PACKET_end(const PACKET *pkt)
{
    return pkt->pk_curr + pkt->pk_remaining;
}

/*
 * Returns a pointer to the PACKET's current position.
 * For use in non-PACKETized APIs.
 */
static inline const fc_u8 *PACKET_data(const PACKET *pkt)
{
    return pkt->pk_curr;
}

/*
 * Initialise a PACKET with |len| bytes held in |buf|. This does not make a
 * copy of the data so |buf| must be present for the whole time that the PACKET
 * is being used.
 */
static inline int PACKET_buf_init(PACKET *pkt, const fc_u8 *buf, size_t len)
{
    /* Sanity check for negative values. */
    if (len > (size_t)(SIZE_MAX / 2)) {
        return 0;
    }

    pkt->pk_curr = buf;
    pkt->pk_remaining = len;
    return 1;
}

/* Initialize a PACKET to hold zero bytes. */
static inline void PACKET_null_init(PACKET *pkt)
{
    pkt->pk_curr = NULL;
    pkt->pk_remaining = 0;
}

/*
 * Peek ahead at 3 bytes in network order from |pkt| and store the value in
 * |*data|
 */
static inline int PACKET_peek_net_3(const PACKET *pkt, fc_ulong *data)
{
    if (PACKET_remaining(pkt) < 3) {
        return 0;
    }

    *data = ((fc_ulong)(*pkt->pk_curr)) << 16;
    *data |= ((fc_ulong)(*(pkt->pk_curr + 1))) << 8;
    *data |= *(pkt->pk_curr + 2);

    return 1;
}

/* Equivalent of n2l3 */
/* Get 3 bytes in network order from |pkt| and store the value in |*data| */
static inline int PACKET_get_net_3(PACKET *pkt, fc_ulong *data)
{
    if (!PACKET_peek_net_3(pkt, data)) {
        return 0;
    }

    packet_forward(pkt, 3);

    return 1;
}

/*
 * Peek ahead at 2 bytes in network order from |pkt| and store the value in
 * |*data|
 */
static inline int PACKET_peek_net_2(const PACKET *pkt, fc_u32 *data)
{
    if (PACKET_remaining(pkt) < 2) {
        return 0;
    }

    *data = ((fc_u32)(*pkt->pk_curr)) << 8;
    *data |= *(pkt->pk_curr + 1);

    return 1;
}

/* Equivalent of n2s */
/* Get 2 bytes in network order from |pkt| and store the value in |*data| */
static inline int PACKET_get_net_2(PACKET *pkt, fc_u32 *data)
{
    if (!PACKET_peek_net_2(pkt, data)) {
        return 0;
    }

    packet_forward(pkt, 2);

    return 1;
}

/* Peek ahead at 1 byte from |pkt| and store the value in |*data| */
static inline int PACKET_peek_1(const PACKET *pkt, fc_u32 *data)
{
    if (!PACKET_remaining(pkt)) {
        return 0;
    }

    *data = *pkt->pk_curr;

    return 1;
}

/* Get 1 byte from |pkt| and store the value in |*data| */
static inline int PACKET_get_1(PACKET *pkt, fc_u32 *data)
{
    if (!PACKET_peek_1(pkt, data)) {
        return 0;
    }

    packet_forward(pkt, 1);

    return 1;
}

/*
 * Peek ahead at 4 bytes in reverse network order from |pkt| and store the value
 * in |*data|
 */
static inline int PACKET_peek_4(const PACKET *pkt, fc_ulong *data)
{
    if (PACKET_remaining(pkt) < 4) {
        return 0;
    }

    *data = *pkt->pk_curr;
    *data |= ((fc_ulong)(*(pkt->pk_curr + 1))) << 8;
    *data |= ((fc_ulong)(*(pkt->pk_curr + 2))) << 16;
    *data |= ((fc_ulong)(*(pkt->pk_curr + 3))) << 24;

    return 1;
}

/* Equivalent of c2l */
/*
 * Get 4 bytes in reverse network order from |pkt| and store the value in
 * |*data|
 */
static inline int PACKET_get_4(PACKET *pkt, fc_ulong *data)
{
    if (!PACKET_peek_4(pkt, data)) {
        return 0;
    }

    packet_forward(pkt, 4);

    return 1;
}

/*
 * Peek ahead at |len| bytes from the |pkt| and store a pointer to them in
 * |*data|. This just points at the underlying buffer that |pkt| is using. The
 * caller should not free this data directly (it will be freed when the
 * underlying buffer gets freed
 */
static inline int PACKET_peek_bytes(const PACKET *pkt, const fc_u8 **data,
                                        size_t len)
{
    if (PACKET_remaining(pkt) < len) {
        return 0;
    }

    *data = pkt->pk_curr;

    return 1;
}

/*
 * Read |len| bytes from the |pkt| and store a pointer to them in |*data|. This
 * just points at the underlying buffer that |pkt| is using. The caller should
 * not free this data directly (it will be freed when the underlying buffer gets
 * freed
 */
static inline int PACKET_get_bytes(PACKET *pkt, const fc_u8 **data,
                                        size_t len)
{
    if (!PACKET_peek_bytes(pkt, data, len)) {
        return 0;
    }

    packet_forward(pkt, len);

    return 1;
}


/* Peek ahead at |len| bytes from |pkt| and copy them to |data| */
static inline int PACKET_peek_copy_bytes(const PACKET *pkt, fc_u8 *data, 
                                            size_t len)
{
    if (PACKET_remaining(pkt) < len) {
        return 0;
    }

    memcpy(data, pkt->pk_curr, len);

    return 1;
}

/*
 * Read |len| bytes from |pkt| and copy them to |data|.
 * The caller is responsible for ensuring that |data| can hold |len| bytes.
 */
static inline int PACKET_copy_bytes(PACKET *pkt, fc_u8 *data, size_t len)
{
    if (!PACKET_peek_copy_bytes(pkt, data, len)) {
        return 0;
    }

    packet_forward(pkt, len);

    return 1;
}

/*
 * Reads a variable-length vector prefixed with a one-byte length, and stores
 * the contents in |subpkt|. |pkt| can equal |subpkt|.
 * Data is not copied: the |subpkt| packet will share its underlying buffer with
 * the original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 * Upon failure, the original |pkt| and |subpkt| are not modified.
 */
static inline int PACKET_get_length_prefixed_1(PACKET *pkt, PACKET *subpkt)
{
    const fc_u8     *data = NULL;
    fc_u32          length = 0;
    PACKET          tmp = *pkt;

    if (!PACKET_get_1(&tmp, &length) ||
        !PACKET_get_bytes(&tmp, &data, (size_t)length)) {
        return 0;
    }

    *pkt = tmp;
    subpkt->pk_curr = data;
    subpkt->pk_remaining = length;

    return 1;
}

/*
 * Reads a variable-length vector prefixed with a two-byte length, and stores
 * the contents in |subpkt|. |pkt| can equal |subpkt|.
 * Data is not copied: the |subpkt| packet will share its underlying buffer with
 * the original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 * Upon failure, the original |pkt| and |subpkt| are not modified.
 */
static inline int PACKET_get_length_prefixed_2(PACKET *pkt, PACKET *subpkt)
{
    const fc_u8     *data;
    fc_u32          length = 0;
    PACKET          tmp = *pkt;

    if (!PACKET_get_net_2(&tmp, &length) ||
        !PACKET_get_bytes(&tmp, &data, (size_t)length)) {
        return 0;
    }

    *pkt = tmp;
    subpkt->pk_curr = data;
    subpkt->pk_remaining = length;

    return 1;
}

/* Writeable packets */

typedef struct wpacket_sub_t WPACKET_SUB;
struct wpacket_sub_t {
    /* The parent WPACKET_SUB if we have one or NULL otherwise */
    WPACKET_SUB     *ws_parent;

    /*
     * Offset into the buffer where the length of this WPACKET goes. We use an
     * offset in case the buffer grows and gets reallocated.
     */
    size_t          ws_packet_len;

    /* Number of bytes in the packet_len or 0 if we don't write the length */
    size_t          ws_lenbytes;

    /* Number of bytes written to the buf prior to this packet starting */
    size_t          ws_pwritten;

    /* Flags for this sub-packet */
    unsigned int    ws_flags;
};

typedef struct wpacket_t {
    /* The buffer where we store the output data */
    FC_BUF_MEM      *wk_buf;

    /* Fixed sized buffer which can be used as an alternative to buf */
    unsigned char   *wk_staticbuf;

    /*
     * Offset into the buffer where we are currently writing. We use an offset
     * in case the buffer grows and gets reallocated.
     */
    size_t          wk_curr;

    /* Number of bytes written so far */
    size_t          wk_written;

    /* Maximum number of bytes we will allow to be written to this WPACKET */
    size_t          wk_maxsize;

    /* Our sub-packets (always at least one if not finished) */
    WPACKET_SUB     *wk_subs;
} WPACKET;

/* Default */
#define WPACKET_FLAGS_NONE                      0

/* Error on WPACKET_close() if no data written to the WPACKET */
#define WPACKET_FLAGS_NON_ZERO_LENGTH           1

/*
 * Abandon all changes on WPACKET_close() if no data written to the WPACKET,
 * i.e. this does not write out a zero packet length
 */
#define WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH    2


/*
 * Initialise a WPACKET with the buffer in |buf|. The buffer must exist
 * for the whole time that the WPACKET is being used. Additionally |lenbytes| of
 * data is preallocated at the start of the buffer to store the length of the
 * WPACKET once we know it.
 */
int WPACKET_init_len(WPACKET *pkt, FC_BUF_MEM *buf, size_t lenbytes);

/*
 * Same as WPACKET_init_len except there is no preallocation of the WPACKET
 * length.
 */
int WPACKET_init(WPACKET *pkt, FC_BUF_MEM *buf);

/*
 * Same as WPACKET_init_len except we do not use a growable BUF_MEM structure.
 * A fixed buffer of memory |buf| of size |len| is used instead. A failure will
 * occur if you attempt to write beyond the end of the buffer
 */
int WPACKET_init_static_len(WPACKET *pkt, unsigned char *buf, size_t len,
                            size_t lenbytes);
/*
 * Set the flags to be applied to the current sub-packet
 */
int WPACKET_set_flags(WPACKET *pkt, unsigned int flags);

/*
 * Closes the most recent sub-packet. It also writes out the length of the
 * packet to the required location (normally the start of the WPACKET) if
 * appropriate. The top level WPACKET should be closed using WPACKET_finish()
 * instead of this function.
 */
int WPACKET_close(WPACKET *pkt);

/*
 * The same as WPACKET_close() but only for the top most WPACKET. Additionally
 * frees memory resources for this WPACKET.
 */
int WPACKET_finish(WPACKET *pkt);

/*
 * Iterate through all the sub-packets and write out their lengths as if they
 * were being closed. The lengths will be overwritten with the final lengths
 * when the sub-packets are eventually closed (which may be different if more
 * data is added to the WPACKET). This function fails if a sub-packet is of 0
 * length and WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH is set.
 */
int WPACKET_fill_lengths(WPACKET *pkt);

/*
 * Initialise a new sub-packet. Additionally |lenbytes| of data is preallocated
 * at the start of the sub-packet to store its length once we know it. Don't
 * call this directly. Use the convenience macros below instead.
 */
int WPACKET_start_sub_packet_len__(WPACKET *pkt, size_t lenbytes);

/*
 * Convenience macros for calling WPACKET_start_sub_packet_len with different
 * lengths
 */
#define WPACKET_start_sub_packet_u8(pkt) \
    WPACKET_start_sub_packet_len__((pkt), 1)
#define WPACKET_start_sub_packet_u16(pkt) \
    WPACKET_start_sub_packet_len__((pkt), 2)
#define WPACKET_start_sub_packet_u24(pkt) \
    WPACKET_start_sub_packet_len__((pkt), 3)
#define WPACKET_start_sub_packet_u32(pkt) \
    WPACKET_start_sub_packet_len__((pkt), 4)

/*
 * Same as WPACKET_start_sub_packet_len__() except no bytes are pre-allocated
 * for the sub-packet length.
 */
int WPACKET_start_sub_packet(WPACKET *pkt);

/*
 * Allocate bytes in the WPACKET for the output. This reserves the bytes
 * and counts them as "written", but doesn't actually do the writing. A pointer
 * to the allocated bytes is stored in |*allocbytes|. |allocbytes| may be NULL.
 * WARNING: the allocated bytes must be filled in immediately, without further
 * WPACKET_* calls. If not then the underlying buffer may be realloc'd and
 * change its location.
 */
int WPACKET_allocate_bytes(WPACKET *pkt, size_t len,
                           unsigned char **allocbytes);

/*
 * The same as WPACKET_allocate_bytes() except additionally a new sub-packet is
 * started for the allocated bytes, and then closed immediately afterwards. The
 * number of length bytes for the sub-packet is in |lenbytes|. Don't call this
 * directly. Use the convenience macros below instead.
 */
int WPACKET_sub_allocate_bytes__(WPACKET *pkt, size_t len,
                                 unsigned char **allocbytes, size_t lenbytes);

/*
 * Convenience macros for calling WPACKET_sub_allocate_bytes with different
 * lengths
 */
#define WPACKET_sub_allocate_bytes_u8(pkt, len, bytes) \
    WPACKET_sub_allocate_bytes__((pkt), (len), (bytes), 1)
#define WPACKET_sub_allocate_bytes_u16(pkt, len, bytes) \
    WPACKET_sub_allocate_bytes__((pkt), (len), (bytes), 2)
#define WPACKET_sub_allocate_bytes_u24(pkt, len, bytes) \
    WPACKET_sub_allocate_bytes__((pkt), (len), (bytes), 3)
#define WPACKET_sub_allocate_bytes_u32(pkt, len, bytes) \
    WPACKET_sub_allocate_bytes__((pkt), (len), (bytes), 4)

/*
 * The same as WPACKET_allocate_bytes() except the reserved bytes are not
 * actually counted as written. Typically this will be for when we don't know
 * how big arbitrary data is going to be up front, but we do know what the
 * maximum size will be. If this function is used, then it should be immediately
 * followed by a WPACKET_allocate_bytes() call before any other WPACKET
 * functions are called (unless the write to the allocated bytes is abandoned).
 *
 * For example: If we are generating a signature, then the size of that
 * signature may not be known in advance. We can use WPACKET_reserve_bytes() to
 * handle this:
 *
 *  if (!WPACKET_sub_reserve_bytes_u16(&pkt, EVP_PKEY_size(pkey), &sigbytes1)
 *          || EVP_SignFinal(md_ctx, sigbytes1, &siglen, pkey) <= 0
 *          || !WPACKET_sub_allocate_bytes_u16(&pkt, siglen, &sigbytes2)
 *          || sigbytes1 != sigbytes2)
 *      goto err;
 */
int WPACKET_reserve_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes);

/*
 * The "reserve_bytes" equivalent of WPACKET_sub_allocate_bytes__()
 */
int WPACKET_sub_reserve_bytes__(WPACKET *pkt, size_t len,
                                 unsigned char **allocbytes, size_t lenbytes);

/*
 * Convenience macros for  WPACKET_sub_reserve_bytes with different lengths
 */
#define WPACKET_sub_reserve_bytes_u8(pkt, len, bytes) \
    WPACKET_reserve_bytes__((pkt), (len), (bytes), 1)
#define WPACKET_sub_reserve_bytes_u16(pkt, len, bytes) \
    WPACKET_sub_reserve_bytes__((pkt), (len), (bytes), 2)
#define WPACKET_sub_reserve_bytes_u24(pkt, len, bytes) \
    WPACKET_sub_reserve_bytes__((pkt), (len), (bytes), 3)
#define WPACKET_sub_reserve_bytes_u32(pkt, len, bytes) \
    WPACKET_sub_reserve_bytes__((pkt), (len), (bytes), 4)

/*
 * Write the value stored in |val| into the WPACKET. The value will consume
 * |bytes| amount of storage. An error will occur if |val| cannot be
 * accommodated in |bytes| storage, e.g. attempting to write the value 256 into
 * 1 byte will fail. Don't call this directly. Use the convenience macros below
 * instead.
 */
int WPACKET_put_bytes__(WPACKET *pkt, unsigned int val, size_t bytes);

/*
 * Convenience macros for calling WPACKET_put_bytes with different
 * lengths
 */
#define WPACKET_put_bytes_u8(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 1)
#define WPACKET_put_bytes_u16(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 2)
#define WPACKET_put_bytes_u24(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 3)
#define WPACKET_put_bytes_u32(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 4)

/* Set a maximum size that we will not allow the WPACKET to grow beyond */
int WPACKET_set_max_size(WPACKET *pkt, size_t maxsize);

/* Copy |len| bytes of data from |*src| into the WPACKET. */
int WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len);

/* Set |len| bytes of data to |ch| into the WPACKET. */
int WPACKET_memset(WPACKET *pkt, int ch, size_t len);

/*
 * Copy |len| bytes of data from |*src| into the WPACKET and prefix with its
 * length (consuming |lenbytes| of data for the length). Don't call this
 * directly. Use the convenience macros below instead.
 */
int WPACKET_sub_memcpy__(WPACKET *pkt, const void *src, size_t len,
                       size_t lenbytes);

/* Convenience macros for calling WPACKET_sub_memcpy with different lengths */
#define WPACKET_sub_memcpy_u8(pkt, src, len) \
    WPACKET_sub_memcpy__((pkt), (src), (len), 1)
#define WPACKET_sub_memcpy_u16(pkt, src, len) \
    WPACKET_sub_memcpy__((pkt), (src), (len), 2)
#define WPACKET_sub_memcpy_u24(pkt, src, len) \
    WPACKET_sub_memcpy__((pkt), (src), (len), 3)
#define WPACKET_sub_memcpy_u32(pkt, src, len) \
    WPACKET_sub_memcpy__((pkt), (src), (len), 4)

/*
 * Return the total number of bytes written so far to the underlying buffer
 * including any storage allocated for length bytes
 */
int WPACKET_get_total_written(WPACKET *pkt, size_t *written);

/*
 * Returns the length of the current sub-packet. This excludes any bytes
 * allocated for the length itself.
 */
int WPACKET_get_length(WPACKET *pkt, size_t *len);

/*
 * Returns a pointer to the current write location, but does not allocate any
 * bytes.
 */
unsigned char *WPACKET_get_curr(WPACKET *pkt);

/* Release resources in a WPACKET if a failure has occurred. */
void WPACKET_cleanup(WPACKET *pkt);


#endif
