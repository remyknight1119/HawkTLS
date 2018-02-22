
#include <falcontls/tls.h>
#include "tls_locl.h"

int
RECORD_LAYER_write_pending(const RECORD_LAYER *rl)
{
    return (rl->rl_numwpipes >= 0) &&
        TLS_BUFFER_get_left(&rl->rl_wbuf[rl->rl_numwpipes - 1]) != 0;
}

