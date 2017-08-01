#ifndef __DV_TLS_LOC_H__
#define __DV_TLS_LOC_H__

#include "dv_ssl.h"
#include "dv_tls.h"

typedef struct _dv_msg_parse_t {
    dv_u8       mp_type;
    int         (*mp_parse)(dv_ssl_t *s, void *buf, dv_u32 len);
} dv_msg_parse_t;

#define dv_implement_tls_meth_func(version, msg_max_len, func_name, \
        accept, connect, hello, parser, get_time, read_f, write_f) \
const dv_method_t *\
func_name(void) \
{ \
    static const dv_method_t func_name##_data = { \
        version, \
        msg_max_len, \
        dv_tls_new, /* md_ssl_new */\
        dv_tls_free, /* md_ssl_free */\
        accept, \
        connect, \
        dv_tls_bio_read, /* md_ssl_read */\
        dv_tls_bio_write, /* md_ssl_write */\
        dv_tls_bio_shutdown, /* md_ssl_shutdown */\
        hello, \
        dv_tls_bio_get_message, \
        parser, \
        get_time, \
        read_f, \
        dv_bio_read_file_linux, \
        write_f, \
    }; \
    \
    return &func_name##_data;\
}

extern void dv_tls_get_cipher_suites(dv_u16 *dest, 
            const dv_u16 *suites, dv_u32 num);
extern bool dv_tls_match_cipher_suites(dv_u16 dest, 
            const dv_u16 *suites, dv_u32 num);
extern int dv_tls_parse_record(dv_ssl_t *s, const dv_msg_parse_t *parser, 
            dv_u32 num);
extern int dv_tls_parse_handshake(dv_ssl_t *s, const dv_msg_parse_t *parser,
            dv_u32 num, void *buf, int total_len);

#endif
