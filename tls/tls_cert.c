

#include <falcontls/tls.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>
#include <falcontls/x509.h>
#include <falcontls/pem.h>
#include <falcontls/types.h>
#include <fc_log.h>

#include "tls_locl.h"

int 
tls_cert_type(const FC_X509 *x, const FC_EVP_PKEY *pk)
{
    if (pk == NULL && (pk = FC_X509_get0_pubkey(x)) == NULL) {
        return -1;
    }

    return FC_EVP_PKEY_id(pk);
}

CERT *
tls_cert_new(void)
{
    CERT *ret = FALCONTLS_calloc(sizeof(*ret));

    if (ret == NULL) {
        FC_LOG("Alloc CERT failed\n");
        return NULL;
    }

    ret->ct_key = &(ret->ct_pkeys[FC_EVP_PKEY_RSA_ENC]);

    return ret;
}

CERT *
tls_cert_dup(CERT *cert)
{
    CERT *ret = FALCONTLS_calloc(sizeof(*ret));
    int i;

    if (ret == NULL) {
        FC_LOG("Alloc CERT failed\n");
        return NULL;
    }

    ret->ct_key = &ret->ct_pkeys[cert->ct_key - cert->ct_pkeys];
#if 0
    if (cert->dh_tmp != NULL) {
        ret->dh_tmp = cert->dh_tmp;
        EVP_PKEY_up_ref(ret->dh_tmp);
    }
    ret->dh_tmp_cb = cert->dh_tmp_cb;
    ret->dh_tmp_auto = cert->dh_tmp_auto;
#endif

    for (i = 0; i < FC_EVP_PKEY_NUM; i++) {
#if 0
        CERT_PKEY *cpk = cert->pkeys + i;
        CERT_PKEY *rpk = ret->pkeys + i;
        if (cpk->x509 != NULL) {
            rpk->x509 = cpk->x509;
            X509_up_ref(rpk->x509);
        }

        if (cpk->privatekey != NULL) {
            rpk->privatekey = cpk->privatekey;
            EVP_PKEY_up_ref(cpk->privatekey);
        }

        if (cpk->chain) {
            rpk->chain = X509_chain_up_ref(cpk->chain);
            if (!rpk->chain) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        if (cert->pkeys[i].serverinfo != NULL) {
            /* Just copy everything. */
            ret->pkeys[i].serverinfo =
                OPENSSL_malloc(cert->pkeys[i].serverinfo_length);
            if (ret->pkeys[i].serverinfo == NULL) {
                SSLerr(SSL_F_SSL_CERT_DUP, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            ret->pkeys[i].serverinfo_length = cert->pkeys[i].serverinfo_length;
            memcpy(ret->pkeys[i].serverinfo,
                   cert->pkeys[i].serverinfo, cert->pkeys[i].serverinfo_length);
        }
#endif
    }

#if 0
    /* Configured sigalgs copied across */
    if (cert->conf_sigalgs) {
        ret->conf_sigalgs = OPENSSL_malloc(cert->conf_sigalgslen);
        if (ret->conf_sigalgs == NULL)
            goto err;
        memcpy(ret->conf_sigalgs, cert->conf_sigalgs, cert->conf_sigalgslen);
        ret->conf_sigalgslen = cert->conf_sigalgslen;
    } else
        ret->conf_sigalgs = NULL;

    if (cert->client_sigalgs) {
        ret->client_sigalgs = OPENSSL_malloc(cert->client_sigalgslen);
        if (ret->client_sigalgs == NULL)
            goto err;
        memcpy(ret->client_sigalgs, cert->client_sigalgs,
               cert->client_sigalgslen);
        ret->client_sigalgslen = cert->client_sigalgslen;
    } else
        ret->client_sigalgs = NULL;
    /* Shared sigalgs also NULL */
    ret->shared_sigalgs = NULL;
    /* Copy any custom client certificate types */
    if (cert->ctypes) {
        ret->ctypes = OPENSSL_malloc(cert->ctype_num);
        if (ret->ctypes == NULL)
            goto err;
        memcpy(ret->ctypes, cert->ctypes, cert->ctype_num);
        ret->ctype_num = cert->ctype_num;
    }

    ret->cert_flags = cert->cert_flags;

    ret->cert_cb = cert->cert_cb;
    ret->cert_cb_arg = cert->cert_cb_arg;

    if (cert->verify_store) {
        X509_STORE_up_ref(cert->verify_store);
        ret->verify_store = cert->verify_store;
    }

    if (cert->chain_store) {
        X509_STORE_up_ref(cert->chain_store);
        ret->chain_store = cert->chain_store;
    }

    ret->sec_cb = cert->sec_cb;
    ret->sec_level = cert->sec_level;
    ret->sec_ex = cert->sec_ex;

    if (!custom_exts_copy(&ret->cli_ext, &cert->cli_ext))
        goto err;
    if (!custom_exts_copy(&ret->srv_ext, &cert->srv_ext))
        goto err;
#ifndef OPENSSL_NO_PSK
    if (cert->psk_identity_hint) {
        ret->psk_identity_hint = OPENSSL_strdup(cert->psk_identity_hint);
        if (ret->psk_identity_hint == NULL)
            goto err;
    }
#endif
#endif
    return ret;
#if 0
 err:
    tls_cert_free(ret);

    return NULL;
#endif
}

/* Free up and clear all certificates and chains */

void 
tls_cert_clear_certs(CERT *c)
{
    int i;

    if (c == NULL) {
        return;
    }

    for (i = 0; i < FC_EVP_PKEY_NUM; i++) {
#if 0
        CERT_PKEY *cpk = c->pkeys + i;
        X509_free(cpk->x509);
        cpk->x509 = NULL;
        EVP_PKEY_free(cpk->privatekey);
        cpk->privatekey = NULL;
        sk_X509_pop_free(cpk->chain, X509_free);
        cpk->chain = NULL;
        OPENSSL_free(cpk->serverinfo);
        cpk->serverinfo = NULL;
        cpk->serverinfo_length = 0;
#endif
    }
}

void 
tls_cert_free(CERT *c)
{
    if (c == NULL) {
        return;
    }

#if 0
    EVP_PKEY_free(c->dh_tmp);
#endif

    tls_cert_clear_certs(c);
#if 0
    OPENSSL_free(c->conf_sigalgs);
    OPENSSL_free(c->client_sigalgs);
    OPENSSL_free(c->shared_sigalgs);
    OPENSSL_free(c->ctypes);
    X509_STORE_free(c->verify_store);
    X509_STORE_free(c->chain_store);
    custom_exts_free(&c->cli_ext);
    custom_exts_free(&c->srv_ext);
#ifndef OPENSSL_NO_PSK
    OPENSSL_free(c->psk_identity_hint);
#endif
    CRYPTO_THREAD_lock_free(c->lock);
#endif
    FALCONTLS_free(c);
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


