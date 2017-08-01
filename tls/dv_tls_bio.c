#include <unistd.h>

#include "dv_ssl.h"
#include "dv_tls.h"
#include "dv_crypto.h"
#include "dv_errno.h"

int
dv_tls_bio_accept(dv_ssl_t *s)
{
    int         len = 0;
    int         wlen = 0;
    int         ret = DV_ERROR;

    while (1) {
        switch (s->ssl_state) {
            case DV_SSL_STATE_INIT:
                ret = s->ssl_method->md_ssl_get_message(s);
                if (ret != DV_OK) {
                    goto end;
                }

                ret = s->ssl_method->md_ssl_parse_message(s);
                if (ret != DV_OK) {
                    goto end;
                }

                len = s->ssl_method->md_ssl_hello(s);
                if (len <= 0) {
                    goto end;
                }

                wlen = s->ssl_method->md_bio_write(s->ssl_fd, s->ssl_msg, len);
                if (wlen < len) {
                    goto end;
                }

                s->ssl_state = DV_SSL_STATE_HELLO;
                break;
            case DV_SSL_STATE_HELLO:
                ret = DV_OK;
                goto end;
                break;
            default:
                ret = DV_ERROR;
                goto end;
        }
    }

end:

    return ret;
}

int
dv_tls_bio_connect(dv_ssl_t *s)
{
    int         len = 0;
    int         wlen = 0;
    int         ret = DV_ERROR;

    while (1) {
        switch (s->ssl_state) {
            case DV_SSL_STATE_INIT:
                len = s->ssl_method->md_ssl_hello(s);
                if (len <= 0) {
                    goto end;
                }
                wlen = s->ssl_method->md_bio_write(s->ssl_fd, s->ssl_msg, len);
                if (wlen < len) {
                    goto end;
                }

                s->ssl_state = DV_SSL_STATE_HELLO;
                break;
            case DV_SSL_STATE_HELLO:
                ret = s->ssl_method->md_ssl_get_message(s);
                if (ret != DV_OK) {
                    goto end;
                }

                ret = s->ssl_method->md_ssl_parse_message(s);
                if (ret != DV_OK) {
                    goto end;
                }

                ret = DV_OK;
                goto end;
                break;
            case DV_SSL_STATE_KEY_EXCHANGE:
                break;
            default:
                ret = DV_ERROR;
                goto end;
        }
    }

end:

    return ret;
}

int
dv_tls_bio_read(dv_ssl_t *s, void *buf, dv_u32 len)
{
    return s->ssl_method->md_bio_read(s->ssl_fd, buf, len);
}

int
dv_tls_bio_write(dv_ssl_t *s, const void *buf, dv_u32 len)
{
    return s->ssl_method->md_bio_write(s->ssl_fd, buf, len);
}

int
dv_tls_bio_shutdown(dv_ssl_t *s)
{
    return DV_OK;
}

int
dv_tls_bio_get_message(dv_ssl_t *s)
{
    int         rlen = 0;

    rlen = s->ssl_method->md_bio_read(s->ssl_fd, s->ssl_msg, 
            s->ssl_method->md_msg_max_len);
    if (rlen <= 0) {
        return DV_ERROR;
    }

    s->ssl_mlen = rlen;

    return DV_OK;
}
