#ifndef __FC_X509_H__
#define __FC_X509_H__

#include <stdint.h>

typedef struct _fc_x509_t {
    uint32_t    x509_version;
    void        *x509_store;
} FC_X509;

extern int fc_d2i_x509(FC_X509 *x509, const uint8_t *data, uint32_t len);

#endif
