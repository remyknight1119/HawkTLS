#ifndef __HK_X509_H__
#define __HK_X509_H__

#include <stdint.h>

typedef struct _hk_x509_t {
    uint32_t    x509_version;
    void        *x509_store;
} hk_x509_t;

extern int hk_d2i_x509(hk_x509_t *x509, const uint8_t *data, uint32_t len);

#endif
