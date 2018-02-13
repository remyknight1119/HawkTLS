#ifndef __FC_PACKET_H__
#define __FC_PACKET_H__

#include <falcontls/types.h>

typedef struct {
    /* Pointer to where we are currently reading from */
    const fc_u8     *pk_curr;
    /* Number of bytes remaining */
    size_t          pk_remaining;
} PACKET;



#endif
