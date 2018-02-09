#ifndef __FC_PEM_H__
#define __FC_PEM_H__

#ifdef FC_OPENSSL
#define FC_PEM_read_bio_X509 PEM_read_bio_X509
#define FC_PEM_read_bio_PrivateKey PEM_read_bio_PrivateKey
#else
#endif

#endif
