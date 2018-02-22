
#include <falcontls/tls.h>
#include <falcontls/x509.h>

#include "tls_locl.h"

TLS_ENC_METHOD const TLSv1_2_enc_data = {
    .em_enc = tls1_enc,
    .em_enc_flags = TLS_ENC_FLAG_EXPLICIT_IV,
};

int
tls1_enc(TLS *s, TLS_RECORD *recs, fc_u32 n_recs, int sending)
{
    return 1;
}

int 
tls_security_cert(TLS *s, TLS_CTX *ctx, FC_X509 *x, int vfy, int is_ee)
{
    return 1;
}

