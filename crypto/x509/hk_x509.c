
#include <openssl/x509.h>

#include "dv_x509.h"
#include "dv_types.h"
#include "dv_errno.h"

int
dv_d2i_x509(dv_x509_t *x509, const dv_u8 *data, dv_u32 len)
{
    X509    *x = NULL;
#if 0
    BIO     *b = NULL;
#endif

    x = d2i_X509(NULL, &data, (long)len);
    if (x == NULL) {
        return DV_ERROR;
    }
    if (x509) {
        //Now without free
        x509->x509_store = x;
    }
#if 0
    b = BIO_new(BIO_s_file());
    BIO_set_fp(b, stdout, BIO_NOCLOSE);
    X509_print(b, x);
    BIO_free(b);
#endif
    //X509_free(x);

    return DV_OK;
}
