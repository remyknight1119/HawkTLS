
#include <openssl/x509.h>

#include "hawktls/hk_x509.h"

int
hk_d2i_x509(hk_x509_t *x509, const uint8_t *data, uint32_t len)
{
    X509    *x = NULL;
#if 0
    BIO     *b = NULL;
#endif

    x = d2i_X509(NULL, &data, (long)len);
    if (x == NULL) {
        return -1;
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

    return 0;
}
