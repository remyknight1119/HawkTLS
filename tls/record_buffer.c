
#include <falcontls/types.h>

#include "record.h"
#include "tls_locl.h"

int
tls_setup_read_buffer(TLS *s)
{
    return 0;
}

int
tls_setup_write_buffer(TLS *s)
{
    return 0;
}

int
tls_setup_buffers(TLS *s)
{
    if (!tls_setup_read_buffer(s)) {
        return 0;
    }
    if (!tls_setup_write_buffer(s)) {
        return 0;
    }

    return 1;
}
