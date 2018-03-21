
#include <falcontls/tls.h>
#include <fc_lib.h>
#include <fc_log.h>

#include "tls1.h"
#include "tls_locl.h"

#define TLS1_2_NUM_CIPHERS  FC_ARRAY_SIZE(tls1_2_ciphers)

static TLS_CIPHER tls1_2_ciphers[] = {
    {
        .cp_name = TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM,
        .cp_id = TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM,
        .cp_algorithm_mkey = TLS_kECDHE,
        .cp_lgorithm_auth = TLS_aECDSA,
        .cp_algorithm_enc = TLS_AES128CCM,
        .cp_algorithm_mac = TLS_AEAD,
        .cp_alg_bits = 128,
        .cp_strength_bits = 128,
    },
    {
    },
};

int 
tls1_2_new(TLS *s)
{
    return 1;
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
    return 1;
}

int
tls1_2_connect(TLS *s)
{
    return 1;
}

int
tls1_2_read(TLS *s, void *buf, int len)
{
    return 1;
}

int
tls1_2_peek(TLS *s, void *buf, int len)
{
    return 1;
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

int
tls1_2_num_ciphers(void)
{
    return TLS1_2_NUM_CIPHERS;
}

/*
 * This function needs to check if the ciphers required are actually
 * available
 */
const TLS_CIPHER *
tls1_2_get_cipher_by_char(const fc_u8 *p)
{
    const TLS_CIPHER    *cp = NULL;
    TLS_CIPHER          c = {};
    fc_u32              id = 0;

    id = 0x03000000 | ((fc_u32)p[0] << 8L) | (fc_u32)p[1];
    c.cp_id = id;
//    cp = OBJ_bsearch_ssl_cipher_id(&c, ssl3_ciphers, SSL3_NUM_CIPHERS);
    return cp;
}

int 
tls1_2_put_cipher_by_char(const TLS_CIPHER *c, fc_u8 *p)
{
    long    l = 0;

    if (p != NULL) {
        l = c->cp_id;
        if ((l & 0xff000000) != 0x03000000) {
            return (0);
        }
        p[0] = ((fc_u8)(l >> 8L)) & 0xFF;
        p[1] = ((fc_u8)(l)) & 0xFF;
    }
    return (2);
}


