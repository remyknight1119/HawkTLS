#ifndef __FC_TYPES_H__
#define __FC_TYPES_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <falcontls/safestack.h>

typedef unsigned long           fc_ulong;
typedef uint64_t                fc_u64;
typedef uint32_t                fc_u32;
typedef unsigned short          fc_u16;
typedef unsigned char           fc_u8;

typedef fc_ulong FC_BN_ULONG;

typedef struct fc_tls_ctx_t TLS_CTX;
typedef struct fc_tls_t TLS;
typedef struct fc_tls_method_t TLS_METHOD;
typedef struct tls_cipher_t TLS_CIPHER;
FC_STACK_OF(TLS_CIPHER);

typedef struct fc_bn_t FC_BIGNUM;
typedef struct fc_dh_t FC_DH;
typedef struct fc_x509_t FC_X509;
typedef struct fc_x509_cinf_t FC_X509_CINF;
typedef struct FC_X509_algor_t FC_X509_ALGOR;

typedef struct fc_buf_mem_t FC_BUF_MEM;
typedef struct fc_evp_peky_t FC_EVP_PKEY;
typedef struct fc_bio_t FC_BIO;
typedef struct fc_bio_method_t FC_BIO_METHOD;
typedef struct fc_evp_cipher_t FC_EVP_CIPHER;
typedef struct fc_evp_cipher_ctx_t FC_EVP_CIPHER_CTX;
typedef struct fc_evp_md_t FC_EVP_MD;
typedef struct fc_evp_md_ctx_t FC_EVP_MD_CTX;
typedef struct FC_ASN1_ITEM_t FC_ASN1_ITEM;

typedef struct fc_asn1_string_t FC_ASN1_BIT_STRING;

#define FC_ARRAY_SIZE(array)    (sizeof(array)/sizeof(array[0]))

#define FC_OPENSSL     1

#endif
