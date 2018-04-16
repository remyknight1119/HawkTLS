#ifndef __INTERNAL_FC_EVP_H__
#define __INTERNAL_FC_EVP_H__

#include <falcontls/types.h>


struct fc_evp_md_t {
    int         md_type;
    int         md_pkey_type;
    int         md_size;
    fc_ulong    md_flags;
    int         (*md_init)(FC_EVP_MD_CTX *ctx);
    int         (*md_update)(FC_EVP_MD_CTX *ctx,
                    const void *data, size_t count);
    int         (*md_final)(FC_EVP_MD_CTX *ctx, fc_u8 *md);
    int         (*md_copy)(FC_EVP_MD_CTX *to, const FC_EVP_MD_CTX *from);
    int         (*md_cleanup)(FC_EVP_MD_CTX *ctx);
    int         md_block_size;
    int         md_ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int         (*md_ctrl) (FC_EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
} /* FC_EVP_MD */ ;

struct fc_evp_cipher_t {
    int         cp_nid;
    int         cp_block_size;
    /* Default value for variable length ciphers */
    int         cp_key_len;
    int         cp_iv_len;
    /* Various flags */
    fc_ulong    cp_flags;
    /* init key */
    int         (*cp_init)(FC_EVP_CIPHER_CTX *ctx, const fc_u8 *key,
                    const fc_u8 *iv, int enc);
    /* encrypt/decrypt data */
    int         (*cp_do_cipher)(FC_EVP_CIPHER_CTX *ctx, fc_u8 *out,
                      const fc_u8 *in, size_t inl);
    /* cleanup ctx */
    int         (*cp_cleanup)(FC_EVP_CIPHER_CTX *);
    /* how big ctx->cipher_data needs to be */
    int         cp_ctx_size;
    /* Populate a ASN1_TYPE with parameters */
    //int         (*cp_set_asn1_parameters)(FC_EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Get parameters from a ASN1_TYPE */
    //int         (*cp_get_asn1_parameters) (FC_EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Miscellaneous operations */
    int         (*cp_ctrl)(FC_EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    /* Application data */
    void        *cp_app_data;
}

#endif
