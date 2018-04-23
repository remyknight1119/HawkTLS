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
    fc_u32          length = 0;
    const fc_u8     *data = NULL;
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


#endif
