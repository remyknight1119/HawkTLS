
#include <falcontls/tls.h>
#include <falcontls/x509.h>
#include <internal/buffer.h>
#include <fc_log.h>

#include "tls_locl.h"

TLS_ENC_METHOD const TLSv1_2_enc_data = {
    .em_enc = tls1_enc,
    .em_mac = tls1_mac,
    .em_set_handshake_header = tls1_set_handshake_header,
    .em_hhlen = TLS_HM_HEADER_LENGTH,
    .em_enc_flags = TLS_ENC_FLAG_EXPLICIT_IV,
};

int
tls1_enc(TLS *s, TLS_RECORD *recs, fc_u32 n_recs, int sending)
{
    return 1;
}

int
tls1_mac(TLS *s, TLS_RECORD *rec, fc_u8 *md, int sending)
{
    return 1;
}

int
tls_fill_hello_random(TLS *s, int server, fc_u8 *result, int len)
{
    return 1;
}

int 
tls_security_cert(TLS *s, TLS_CTX *ctx, FC_X509 *x, int vfy, int is_ee)
{
    return 1;
}

int
tls1_set_handshake_header(TLS *s, int htype, fc_ulong len)
{
    fc_u8   *p = (fc_u8 *)s->tls_init_buf->bm_data;

    *(p++) = htype;
    l2n3(len, p);
    s->tls_init_num = (int)len + TLS_HM_HEADER_LENGTH;
    s->tls_init_off = 0;

    return 1;
}

int
tls_cipher_disabled(TLS *s, const TLS_CIPHER *c, int op, int ecdhe)
{
    return 0;
}

