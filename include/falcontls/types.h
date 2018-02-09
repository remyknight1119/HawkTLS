#ifndef __FC_TYPES_H__
#define __FC_TYPES_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

typedef unsigned long           fc_ulong;
typedef uint64_t                fc_u64;
typedef uint32_t                fc_u32;
typedef unsigned short          fc_u16;
typedef unsigned char           fc_u8;

typedef fc_ulong FC_BN_ULONG;

typedef struct fc_tls_ctx_t TLS_CTX;
typedef struct fc_tls_t TLS;
typedef struct fc_tls_method_t TLS_METHOD;

#define FC_OPENSSL     1

#ifdef FC_OPENSSL
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/ossl_typ.h>

typedef X509 FC_X509;
typedef BIO FC_BIO;
typedef BIO_METHOD FC_BIO_METHOD;
typedef EVP_PKEY FC_EVP_PKEY;
#else  //FC_OPENSSL
typedef struct fc_x509_t FC_X509;
typedef struct fc_bio_t FC_BIO;
typedef struct fc_bio_method_t FC_BIO_METHOD;
#endif//FC_OPENSSL

#endif
