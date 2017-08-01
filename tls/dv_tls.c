
#include "dv_tls_loc.h"
#include "dv_tls1_2_proto.h"
#include "dv_tls.h"
#include "dv_bio.h"
#include "dv_types.h"
#include "dv_lib.h"
#include "dv_crypto.h"
#include "dv_errno.h"
#include "dv_debug.h"

int
dv_tls_new(dv_ssl_t *s)
{
    s->ssl_msg = dv_malloc(s->ssl_method->md_msg_max_len);
    if (s->ssl_msg == NULL) {
        return DV_ERROR;
    }

    return DV_OK;
}

void
dv_tls_free(dv_ssl_t *s)
{
    if (s->ssl_msg) {
        dv_free(s->ssl_msg);
    }
}

void
dv_tls_get_cipher_suites(dv_u16 *dest, const dv_u16 *suites, dv_u32 num)
{
    int             i = 0;

    for (i = 0; i < num; i++) {
        dest[i] = DV_HTONS(suites[i]);
    }
}

bool
dv_tls_match_cipher_suites(dv_u16 dest, const dv_u16 *suites, dv_u32 num)
{
    int             i = 0;

    for (i = 0; i < num; i++) {
        if (dest == suites[i]) {
            return DV_TRUE;
        }
    }

    return DV_FALSE;
}


static int
dv_tls_version_check(dv_ssl_t *s, dv_u16 version)
{
    version = DV_NTOHS(version);
    if (version != DV_TLS1_0_VERSION && version != s->ssl_method->md_version) {
        DV_DEBUG("TLS version(%X) invalid!\n", version);
        return DV_ERROR;
    }

    return DV_OK;
}

static int
dv_tls_parse_msg(dv_ssl_t *s, const dv_msg_parse_t *parser, dv_u32 num,
            dv_u32 type, void *buf, dv_u32 len)
{
    int         i = 0;

    for (i = 0; i < num; i++) {
        if (parser->mp_type == type) {
            return parser->mp_parse(s, buf, len);
        }
    }

    return DV_ERROR;
}

int
dv_tls_parse_record(dv_ssl_t *s, const dv_msg_parse_t *parser, dv_u32 num)
{
    dv_tls_record_header_t      *rh = NULL;
    dv_u16                      len = 0;
    int                         total_len = 0;
    int                         ret = DV_OK;

    rh = s->ssl_msg;
    total_len = s->ssl_mlen - sizeof(*rh);
    if (total_len <= 0) {
        return DV_ERROR;
    }

    while (total_len > 0) {
        ret = dv_tls_version_check(s, rh->rh_version.pv_version);
        if (ret != DV_OK) {
            return DV_ERROR;
        }

        len = DV_NTOHS(rh->rh_length);
        if (len > total_len) {
            DV_DEBUG("Size error!(len is %u, total_len is %u)\n", 
                    len, total_len);
            return DV_ERROR;
        }
        ret = dv_tls_parse_msg(s, parser, num, rh->rh_content_type,
                rh + 1, len);
        if (ret != DV_OK) {
            return DV_ERROR;
        }
        total_len -= len;
        rh = (void *)rh + len;
    }

    return DV_OK;
}

int
dv_tls_parse_handshake(dv_ssl_t *s, const dv_msg_parse_t *parser, dv_u32 num,
            void *buf, int total_len)
{
    dv_tls_handshake_header_t   *hh = NULL;
    dv_u32                      len = 0;
    int                         ret = DV_OK;

    hh = buf;
    total_len -= sizeof(*hh);
    if (total_len <= 0) {
        return DV_ERROR;
    }

    while (total_len > 0) {
        DV_GET_LENGTH(len, hh->hh_length);
        if (len > total_len) {
            DV_DEBUG("Size error!(len is %u, total_len is %u)\n", 
                    len, total_len);
            return DV_ERROR;
        }
        ret = dv_tls_parse_msg(s, parser, num, hh->hh_msg_type,
                hh + 1, len);
        if (ret != DV_OK) {
            return DV_ERROR;
        }
        total_len -= len;
        hh = (void *)hh + len;
    }

    return DV_OK;
}


dv_implement_tls_meth_func(DV_TLS1_2_VERSION, DV_TLS_MSG_MAX_LEN, 
        dv_tls_v1_2_client_method, dv_undefined_function, dv_tls_bio_connect,
        dv_tls1_2_client_hello, dv_tls1_2_parse_message, dv_bio_get_time_linux,
        dv_bio_read_sock, dv_bio_write_sock)
dv_implement_tls_meth_func(DV_TLS1_2_VERSION, DV_TLS_MSG_MAX_LEN,
        dv_tls_v1_2_server_method, dv_tls_bio_accept, dv_undefined_function,
        dv_tls1_2_server_hello, dv_tls1_2_parse_message, dv_bio_get_time_linux, 
        dv_bio_read_sock, dv_bio_write_sock)
