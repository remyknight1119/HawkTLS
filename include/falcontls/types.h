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

typedef struct fc_x509_t FC_X509;
typedef struct fc_buf_mem_t FC_BUF_MEM;
typedef struct fc_evp_peky_t FC_EVP_PKEY;
typedef struct fc_bio_t FC_BIO;
typedef struct fc_bio_method_t FC_BIO_METHOD;

#define FC_OPENSSL     1

#ifdef FC_OPENSSL
#else  //FC_OPENSSL
#endif//FC_OPENSSL

#endif
