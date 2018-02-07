#ifndef __FC_TLS_LOCL_H__
#define __FC_TLS_LOCL_H__

#include "falcontls/tls.h"

# define IMPLEMENT_tls_meth_func(version, flags, mask, func_name, s_accept, \
                                 s_connect, enc_data) \
const TLS_METHOD *func_name(void)  \
        { \
        static const TLS_METHOD func_name##_data= { \
                .md_version = version, \
                .md_flags = flags, \
                .md_mask = mask,  \
                .md_tls_new = tls1_2_new, \
                .md_tls_clear = tls1_2_clear, \
                .md_tls_free = tls1_2_free, \
                .md_tls_accept = s_accept, \
                .md_tls_connect = s_connect, \
                .md_tls_read = tls1_2_read, \
                .md_tls_peek = tls1_2_peek, \
                .md_tls_write = tls1_2_write, \
                .md_tls_shutdown = tls1_2_shutdown, \
                .md_tls_renegotiate = tls1_2_renegotiate, \
                .md_tls_renegotiate_check = tls1_2_renegotiate_check, \
                .md_tls_read_bytes = tls1_2_read_bytes, \
                .md_tls_write_bytes = tls1_2_write_bytes, \
                .md_tls_dispatch_alert = tls1_2_dispatch_alert, \
                .md_tls_ctrl = tls1_2_ctrl, \
        }; \
        return &func_name##_data; \
        }


int tls1_2_new(TLS *s);
void tls1_2_clear(TLS *s);
void tls1_2_free(TLS *s);
int tls1_2_accept(TLS *s);
int tls1_2_connect(TLS *s);
int tls1_2_read(TLS *s, void *buf, int len);
int tls1_2_peek(TLS *s, void *buf, int len);
int tls1_2_write(TLS *s, const void *buf, int len);
int tls1_2_shutdown(TLS *s);
int tls1_2_renegotiate(TLS *s);
int tls1_2_renegotiate_check(TLS *s);
int tls1_2_read_bytes(TLS *s, int type, int *recvd_type,
        unsigned char *buf, int len, int peek);
int tls1_2_write_bytes(TLS *s, int type, const void *buf, int len);
int tls1_2_dispatch_alert(TLS *s);
long tls1_2_ctrl(TLS *s, int cmd, long larg, void *parg);



#endif
