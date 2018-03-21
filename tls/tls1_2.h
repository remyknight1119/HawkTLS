#ifndef __TLS1_2_H__
#define __TLS1_2_H__

#include <falcontls/types.h>

#define TLS_RT_HEADER_LENGTH                5

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
int tls1_2_dispatch_alert(TLS *s);
long tls1_2_ctrl(TLS *s, int cmd, long larg, void *parg);
int tls1_2_num_ciphers(void);
const TLS_CIPHER *tls1_2_get_cipher_by_char(const fc_u8 *p);
int tls1_2_put_cipher_by_char(const TLS_CIPHER *c, fc_u8 *p);

#endif
