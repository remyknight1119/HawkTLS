#ifndef __FC_RECORD_H__
#define __FC_RECORD_H__

#include <falcontls/types.h>

typedef struct record_layer_t {
    TLS     *rl_tls;
} RECORD_LAYER;

int tls_setup_buffers(TLS *s);


#endif
