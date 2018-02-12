#include <string.h>

#include <falcontls/types.h>
#include <falcontls/crypto.h>

#include "record_locl.h"
#include "tls_locl.h"

int
tls_setup_read_buffer(TLS *s)
{
    fc_u8       *p = NULL;
    TLS_BUFFER  *b = NULL;
    size_t      len = 0;
    size_t      headerlen = 0;

    b = RECORD_LAYER_get_rbuf(&s->tls_rlayer);

    headerlen = FC_TLS_RT_HEADER_LENGTH;
    if (b->bf_buf == NULL) {
        len = FC_TLS_RT_MAX_PLAIN_LENGTH + FC_TLS_RT_MAX_ENCRYPTED_OVERHEAD +
            headerlen;
        if (b->bf_default_len > len) {
            b->bf_default_len = len;
        }

        if ((p = FALCONTLS_malloc(len)) == NULL) {
            goto err;
        }
        b->bf_buf = p;
        b->bf_len = len;
    }

    RECORD_LAYER_set_packet(&s->tls_rlayer, &(b->bf_buf[0]));
    return 1;
err:
    return 0;
}

int
tls_setup_write_buffer(TLS *s, fc_u32 numwpipes, size_t len)
{
    fc_u8       *p = NULL;
    TLS_BUFFER  *wb = NULL;
    TLS_BUFFER  *thiswb = NULL;
    size_t      headerlen = 0;
    fc_u32      currpipe = 0;

    s->tls_rlayer.rl_numwpipes = numwpipes;
    if (len == 0) {
        headerlen = FC_TLS_RT_HEADER_LENGTH;
        len = s->tls_max_send_fragment + FC_TLS_RT_SEND_MAX_ENCRYPTED_OVERHEAD +
            headerlen;
    }
    wb = RECORD_LAYER_get_wbuf(&s->tls_rlayer);
    for (currpipe = 0; currpipe < numwpipes; currpipe++) {
        thiswb = &wb[currpipe];
        if (thiswb->bf_buf == NULL) {
            if ((p = FALCONTLS_malloc(len)) == NULL) {
                s->tls_rlayer.rl_numwpipes = currpipe;
                goto err;
            }
            memset(thiswb, 0, sizeof(*thiswb));
            thiswb->bf_buf = p;
            thiswb->bf_len = len;
        }
    }

    return 1;
err:
    return 0;
}

int
tls_setup_buffers(TLS *s)
{
    if (!tls_setup_read_buffer(s)) {
        return 0;
    }
    if (!tls_setup_write_buffer(s, 1, 0)) {
        return 0;
    }

    return 1;
}
