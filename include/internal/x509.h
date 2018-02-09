#ifndef __FC_INTERNAL_X509_H__
#define __FC_INTERNAL_X509_H__

#include <falcontls/types.h>

struct fc_x509_t {
    fc_u32      x509_version;
    void        *x509_store;
};

extern int fc_d2i_x509(FC_X509 *x509, const fc_u8 *data, fc_u32 len);

#endif
