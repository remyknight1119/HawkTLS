
#include <falcontls/tls.h>
#include "tls_locl.h"

int 
tls1_2_new(TLS *s)
{
    return 0;
}

void
tls1_2_clear(TLS *s)
{
}

void
tls1_2_free(TLS *s)
{
}

int
tls1_2_accept(TLS *s)
{
    return 0;
}

int
tls1_2_connect(TLS *s)
{
    return 0;
}

int
tls1_2_read(TLS *s, void *buf, int len)
{
    return 0;
}

int
tls1_2_peek(TLS *s, void *buf, int len)
{
    return 0;
}

int
tls1_2_write(TLS *s, const void *buf, int len)
{
    return s->tls_method->md_tls_write_bytes(s, TLS_RT_APPLICATION_DATA,
                buf, len);
}

int
tls1_2_shutdown(TLS *s)
{
    return 0;
}

int
tls1_2_renegotiate(TLS *s)
{
    return 0;
}

int
tls1_2_renegotiate_check(TLS *s)
{
    return 0;
}

int
tls1_2_dispatch_alert(TLS *s)
{
    return 0;
}

long
tls1_2_ctrl(TLS *s, int cmd, long larg, void *parg)
{
    return 0;
}


