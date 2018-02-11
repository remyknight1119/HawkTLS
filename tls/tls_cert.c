

#include <falcontls/tls.h>
#include <falcontls/bio.h>
#include <falcontls/x509.h>
#include <falcontls/pem.h>
#include <falcontls/types.h>

#include "tls_locl.h"

int 
tls_cert_type(const FC_X509 *x, const FC_EVP_PKEY *pk)
{
    if (pk == NULL && (pk = FC_X509_get0_pubkey(x)) == NULL) {
        return -1;
    }

    return FC_EVP_PKEY_id(pk);
}

static int
tls_set_cert(CERT *c, FC_X509 *x)
{
    FC_EVP_PKEY     *pkey = NULL;
    int             i = 0;

    pkey = FC_X509_get0_pubkey(x);
    if (pkey == NULL) {
        return (0);
    }

    i = tls_cert_type(x, pkey);
    if (i < 0) {
        return 0;
    }

#if 0
    if (i == FC_PKEY_ECC && !EC_KEY_can_sign(EVP_PKEY_get0_EC_KEY(pkey))) {
        return 0;
    }
#endif

    if (c->ct_pkeys[i].cp_privatekey != NULL) {
#if 0
        /*
         * The return code from EVP_PKEY_copy_parameters is deliberately
         * ignored. Some EVP_PKEY types cannot do this.
         */
        EVP_PKEY_copy_parameters(pkey, c->pkeys[i].privatekey);
        if (EVP_PKEY_id(c->pkeys[i].privatekey) == EVP_PKEY_RSA
            && RSA_flags(EVP_PKEY_get0_RSA(c->pkeys[i].privatekey)) &
            RSA_METHOD_FLAG_NO_CHECK) ;
        else if (!X509_check_private_key(x, c->pkeys[i].privatekey)) {
            /*
             * don't fail for a cert/key mismatch, just free current private
             * key (when switching to a different cert & key, first this
             * function should be used, then ssl_set_pkey
             */
            EVP_PKEY_free(c->ct_pkeys[i].cp_privatekey);
            c->ct_pkeys[i].cp_privatekey = NULL;
        }
#endif
    }

    FC_X509_free(c->ct_pkeys[i].cp_x509);
//    X509_up_ref(x);
    c->ct_pkeys[i].cp_x509 = x;
    c->ct_key = &(c->ct_pkeys[i]);

    return 1;
}

static int tls_set_pkey(CERT *c, FC_EVP_PKEY *pkey)
{
    int i;
    
    i = tls_cert_type(NULL, pkey);
    if (i < 0) {
        return (0);
    }

    if (c->ct_pkeys[i].cp_x509 != NULL) {
#if 0
        EVP_PKEY *pktmp;
        pktmp = X509_get0_pubkey(c->pkeys[i].x509);
        if (pktmp == NULL) {
            SSLerr(SSL_F_SSL_SET_PKEY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        /*
         * The return code from EVP_PKEY_copy_parameters is deliberately
         * ignored. Some EVP_PKEY types cannot do this.
         */
        EVP_PKEY_copy_parameters(pktmp, pkey);

        /*
         * Don't check the public/private key, this is mostly for smart
         * cards.
         */
        if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA
            && RSA_flags(EVP_PKEY_get0_RSA(pkey)) & RSA_METHOD_FLAG_NO_CHECK) ;
        else
        if (!X509_check_private_key(c->pkeys[i].x509, pkey)) {
            X509_free(c->pkeys[i].x509);
            c->pkeys[i].x509 = NULL;
            return 0;
        }
#endif
    }

    FC_EVP_PKEY_free(c->ct_pkeys[i].cp_privatekey);
    //EVP_PKEY_up_ref(pkey);
    c->ct_pkeys[i].cp_privatekey = pkey;
    c->ct_key = &(c->ct_pkeys[i]);

    return (1);
}

int
FCTLS_use_certificate(TLS *s, FC_X509 *x)
{
    int rv = 0;

    if (x == NULL) {
        return (0);
    }

    rv = tls_security_cert(s, NULL, x, 0, 1);
    if (rv != 1) {
        return 0;
    }

    return (tls_set_cert(s->tls_cert, x));
}

int
FCTLS_CTX_use_certificate(TLS_CTX *ctx, FC_X509 *x)
{
    int rv = 0;

    if (x == NULL) {
        return (0);
    }

    rv = tls_security_cert(NULL, ctx, x, 0, 1);
    if (rv != 1) {
        return 0;
    }

    return (tls_set_cert(ctx->sc_cert, x));
}

int
FCTLS_CTX_use_certificate_file(TLS_CTX *ctx, const char *file, 
        fc_u32 type)
{
    FC_BIO      *in = NULL;
    FC_X509     *x = NULL;
    int         ret = 0;
    
    in = FC_BIO_new(FC_BIO_s_file());
    if (in == NULL) {
        goto end;
    }

    if (FC_BIO_read_filename(in, file) <= 0) {
        goto end;
    }

    if (type == FC_X509_FILETYPE_ASN1) {
    } else if (type == FC_X509_FILETYPE_PEM) {
        x = FC_PEM_read_bio_X509(in, NULL, NULL, NULL); 
    } else {
        goto end;
    }

    ret = FCTLS_CTX_use_certificate(ctx, x);
    FC_X509_free(x);
end:
    FC_BIO_free(in);
    return ret;
}

int
FCTLS_CTX_use_PrivateKey(TLS_CTX *ctx, FC_EVP_PKEY *pkey)
{
    if (pkey == NULL) {
        return (0);
    }

    return (tls_set_pkey(ctx->sc_cert, pkey));
}

int
FCTLS_CTX_use_PrivateKey_file(TLS_CTX *ctx, const char *file, 
        fc_u32 type)
{
    FC_BIO      *in = NULL;
    FC_EVP_PKEY *pkey = NULL;
    int         ret = 0;
    
    in = FC_BIO_new(FC_BIO_s_file());
    if (in == NULL) {
        goto end;
    }

    if (FC_BIO_read_filename(in, file) <= 0) {
        goto end;
    }

    if (type == FC_X509_FILETYPE_ASN1) {
    } else if (type == FC_X509_FILETYPE_PEM) {
        pkey = FC_PEM_read_bio_PrivateKey(in, NULL, NULL, NULL); 
    } else {
        goto end;
    }

    ret = FCTLS_CTX_use_PrivateKey(ctx, pkey);
    FC_EVP_PKEY_free(pkey);
end:
    FC_BIO_free(in);
    return ret;
}


