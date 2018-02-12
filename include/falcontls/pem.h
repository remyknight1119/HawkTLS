#ifndef __FC_PEM_H__
#define __FC_PEM_H__

#include <falcontls/types.h>

typedef int fc_pem_password_cb(char *buf, int size, int flag, void *userdata);

extern FC_X509 *FC_PEM_read_bio_X509(FC_BIO *bp, FC_X509 **x, 
            fc_pem_password_cb *cb, void *u);
extern FC_EVP_PKEY *FC_PEM_read_bio_PrivateKey(FC_BIO *bp, FC_EVP_PKEY **x,
            fc_pem_password_cb *cb, void *u);


#endif
