
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <falcontls/tls.h>
#include <fc_log.h>

#include "tls_test.h"

#define FC_DEF_SERVER_CIPHERS   "ECDHE-RSA-AES128-GCM-SHA256"

static void fc_openssl_add_all_algorighms(void);
static void *fc_openssl_ctx_client_new(void);
static void *fc_openssl_ctx_server_new(void);
static int fc_openssl_ctx_use_certificate_file(void *ctx, const char *file);
static int fc_openssl_ctx_use_privateKey_file(void *ctx, const char *file);
static int fc_openssl_ctx_check_private_key(const void *ctx);
static int fc_openssl_ctx_set_ciphers(void *ctx);
static void *fc_openssl_new(void *ctx);
static int fc_openssl_set_fd(void *s, int fd);
static int fc_openssl_accept(void *s);
static int fc_openssl_connect(void *s);
static int fc_openssl_read(void *s, void *buf, int num);
static int fc_openssl_write(void *s, const void *buf, int num);
static int fc_openssl_shutdown(void *s);
static void fc_openssl_free(void *s);
static void fc_openssl_ctx_free(void *ctx);
static void fc_openssl_set_verify(void *s, int mode, char *peer_cf);
static int fc_openssl_get_verify_result(void *s);

static int fc_tls_library_init(void);
static void fc_tls_add_all_algorighms(void);
static void fc_load_error_strings(void);
static void *fc_tls_ctx_client_new(void);
static void *fc_tls_ctx_server_new(void);
static int fc_tls_ctx_use_certificate_file(void *ctx, const char *file);
static int fc_tls_ctx_use_privateKey_file(void *ctx, const char *file);
static int fc_tls_ctx_check_private_key(const void *ctx);
static int fc_tls_ctx_set_ciphers(void *ctx);
static void *fc_tls_new(void *ctx);
static int fc_tls_set_fd(void *s, int fd);
static int fc_tls_accept(void *s);
static int fc_tls_connect(void *s);
static int fc_tls_read(void *s, void *buf, int num);
static int fc_tls_write(void *s, const void *buf, int num);
static int fc_tls_shutdown(void *s);
static void fc_tls_free(void *s);
static void fc_tls_ctx_free(void *ctx);
static void fc_tls_set_verify(void *s, int mode, char *peer_cf);
static int fc_tls_get_verify_result(void *s);

const PROTO_SUITE fc_openssl_suite = {
    .ps_verify_mode = SSL_VERIFY_PEER,
    .ps_library_init = SSL_library_init,
    .ps_add_all_algorithms = fc_openssl_add_all_algorighms,
    .ps_load_error_strings = SSL_load_error_strings,
    .ps_ctx_client_new = fc_openssl_ctx_client_new,
    .ps_ctx_server_new = fc_openssl_ctx_server_new,
    .ps_ctx_use_certificate_file = fc_openssl_ctx_use_certificate_file,
    .ps_ctx_use_privateKey_file = fc_openssl_ctx_use_privateKey_file,
    .ps_ctx_check_private_key = fc_openssl_ctx_check_private_key,
    .ps_ctx_set_ciphers = fc_openssl_ctx_set_ciphers,
    .ps_ssl_new = fc_openssl_new,
    .ps_set_fd = fc_openssl_set_fd,
    .ps_accept = fc_openssl_accept,
    .ps_connect = fc_openssl_connect,
    .ps_read = fc_openssl_read,
    .ps_write = fc_openssl_write,
    .ps_shutdown = fc_openssl_shutdown,
    .ps_ssl_free = fc_openssl_free,
    .ps_ctx_free = fc_openssl_ctx_free,
    .ps_set_verify = fc_openssl_set_verify,
    .ps_get_verify_result = fc_openssl_get_verify_result,
};

const PROTO_SUITE fc_tls_suite = {
    .ps_verify_mode = 0,
    .ps_library_init = fc_tls_library_init,
    .ps_add_all_algorithms = fc_tls_add_all_algorighms,
    .ps_load_error_strings = fc_load_error_strings,
    .ps_ctx_client_new = fc_tls_ctx_client_new,
    .ps_ctx_server_new = fc_tls_ctx_server_new,
    .ps_ctx_use_certificate_file = fc_tls_ctx_use_certificate_file,
    .ps_ctx_use_privateKey_file = fc_tls_ctx_use_privateKey_file,
    .ps_ctx_check_private_key = fc_tls_ctx_check_private_key,
    .ps_ctx_set_ciphers = fc_tls_ctx_set_ciphers,
    .ps_ssl_new = fc_tls_new,
    .ps_set_fd = fc_tls_set_fd,
    .ps_accept = fc_tls_accept,
    .ps_connect = fc_tls_connect,
    .ps_read = fc_tls_read,
    .ps_write = fc_tls_write,
    .ps_shutdown = fc_tls_shutdown,
    .ps_ssl_free = fc_tls_free,
    .ps_ctx_free = fc_tls_ctx_free,
    .ps_set_verify = fc_tls_set_verify,
    .ps_get_verify_result = fc_tls_get_verify_result,
};

static int
fc_openssl_callback(int ok, X509_STORE_CTX *ctx)
{
    return 1;
}

/* OpenTLS */
static void
fc_openssl_add_all_algorighms(void)
{
    OpenSSL_add_all_algorithms();
}

static void *
fc_openssl_ctx_client_new(void)
{
    return SSL_CTX_new(TLSv1_2_client_method());
}

static void *
fc_openssl_ctx_server_new(void)
{
    return SSL_CTX_new(TLSv1_2_server_method());
}

static int 
fc_openssl_ctx_use_certificate_file(void *ctx, const char *file)
{
    int     ret = 0;

    ret = SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
    if (ret <= 0) {
        return FC_ERROR;
    }

    return FC_OK;
}

static int
fc_openssl_ctx_use_privateKey_file(void *ctx, const char *file)
{
    int     ret = 0;

    ret = SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM);
    if (ret <= 0) {
        return FC_ERROR;
    }

    return FC_OK;
}

static int 
fc_openssl_ctx_set_ciphers(void *ctx)
{    
    int      nid = 0;
    EC_KEY  *ecdh = NULL;
    char    *name = "prime256v1";

    if (SSL_CTX_set_cipher_list(ctx, FC_DEF_SERVER_CIPHERS) == 0) {
        FC_LOG("Set cipher %s\n", FC_DEF_SERVER_CIPHERS);
        return FC_ERROR;
    }

    /*
     * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
     * from RFC 4492 section 5.1.1, or explicitly described curves over
     * binary fields. OpenSSL only supports the "named curves", which provide
     * maximum interoperability.
     */

    nid = OBJ_sn2nid((const char *)name);
    if (nid == 0) {
        FC_LOG("Nid error!\n");
        return FC_ERROR;
    }

    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == NULL) {
        FC_LOG("Unable to create curve \"%s\"", name);
        return FC_ERROR;
    }

    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);

    SSL_CTX_set_tmp_ecdh(ctx, ecdh);

    EC_KEY_free(ecdh);

    return FC_OK;
}

static int
fc_openssl_ctx_check_private_key(const void *ctx)
{
    int     ret = 0;

    ret = SSL_CTX_check_private_key(ctx);
    if (ret == 0) {
        return FC_ERROR;
    }

    return FC_OK;
}

static void *
fc_openssl_new(void *ctx)
{
    return SSL_new(ctx);
}

static int
fc_openssl_set_fd(void *s, int fd)
{
    return SSL_set_fd(s, fd);
}

static int
fc_openssl_accept(void *s)
{
    return SSL_accept(s);
}

static int
fc_openssl_connect(void *s)
{
    return SSL_connect(s);
}

static int
fc_openssl_read(void *s, void *buf, int num)
{
    return SSL_read(s, buf, num);
}

static int
fc_openssl_write(void *s, const void *buf, int num)
{
    return SSL_write(s, buf, num);
}

static int
fc_openssl_shutdown(void *s)
{
    return SSL_shutdown(s);
}

static void
fc_openssl_free(void *s)
{
    SSL_free(s);
}

static void
fc_openssl_ctx_free(void *ctx)
{
    SSL_CTX_free(ctx);
}

static void 
fc_openssl_set_verify(void *ctx, int mode, char *peer_cf)
{
    STACK_OF(X509_NAME)  *list = NULL;

    SSL_CTX_set_verify(ctx, mode, fc_openssl_callback);
    SSL_CTX_set_verify_depth(ctx, 1);

    if (SSL_CTX_load_verify_locations(ctx, peer_cf, NULL) == 0) {
        FC_LOG("Load verify locations %s failed\n", peer_cf);
        exit(1);
    }
    
    list = SSL_load_client_CA_file(peer_cf);
    if (list == NULL) {
        FC_LOG("Load client ca file %s failed\n", peer_cf);
        exit(1);
    }

    SSL_CTX_set_client_CA_list(ctx, list);
}

static int
fc_openssl_get_verify_result(void *s)
{
    long    ret = 0;

    ret = SSL_get_verify_result(s);
    if (ret != X509_V_OK) {
        FC_LOG("Verify ret is %ld\n", ret);
        return FC_ERROR;
    }

    return FC_OK;
}

/* FalconTLS */
static int
fc_tls_library_init(void)
{
    int     ret = 0;

    ret = FALCONTLS_init();
    if (ret != 1) {
        FC_LOG("Init failed\n");
        return FC_ERROR;
    }

    return FC_OK;
}

static void
fc_tls_add_all_algorighms(void)
{
    FalconTLS_add_all_algorighms();
}

static void
fc_load_error_strings(void)
{
}

static void *
fc_tls_ctx_client_new(void)
{
    return FCTLS_CTX_new(FCTLS_method());
}

static void *
fc_tls_ctx_server_new(void)
{
    return FCTLS_CTX_new(FCTLS_method());
}

static int 
fc_tls_ctx_use_certificate_file(void *ctx, const char *file)
{
    int     ret = 0;

    ret = FCTLS_CTX_use_certificate_file(ctx, file, FC_X509_FILETYPE_PEM);
    if (ret != 1) {
        FC_LOG("Verify ret is %d\n", ret);
        return FC_ERROR;
    }

    return FC_OK;
}

static int
fc_tls_ctx_use_privateKey_file(void *ctx, const char *file)
{
    int     ret = 0;

    ret = FCTLS_CTX_use_PrivateKey_file(ctx, file, FC_X509_FILETYPE_PEM);
    if (ret == 0) {
        FC_LOG("Failed!\n");
        return FC_ERROR;
    }

    return FC_OK;
}

static int
fc_tls_ctx_set_ciphers(void *ctx)
{
    return FC_OK;
}

static int
fc_tls_ctx_check_private_key(const void *ctx)
{
    int     ret = 0;

    ret = FCTLS_CTX_check_private_key(ctx);
    if (ret == 0) {
        FC_LOG("Failed!\n");
        return FC_ERROR;
    }

    return FC_OK;
}

static void *
fc_tls_new(void *ctx)
{
    return FCTLS_new(ctx);
}

static int
fc_tls_set_fd(void *s, int fd)
{
    return FCTLS_set_fd(s, fd);
}

static int
fc_tls_accept(void *s)
{
    return FCTLS_accept(s);
}

static int
fc_tls_connect(void *s)
{
    return FCTLS_connect(s);
}

static int
fc_tls_read(void *s, void *buf, int num)
{
    return FCTLS_read(s, buf, num);
}

static int
fc_tls_write(void *s, const void *buf, int num)
{
    return FCTLS_write(s, buf, num);
}

static int
fc_tls_shutdown(void *s)
{
    int     ret = 0;

    ret = FCTLS_shutdown(s);
    if (ret == 0) {
        FC_LOG("Failed!\n");
        return FC_ERROR;
    }

    return FC_OK;
}

static void
fc_tls_free(void *s)
{
    FCTLS_free(s);
}

static void
fc_tls_ctx_free(void *ctx)
{
    FCTLS_CTX_free(ctx);
}

static void 
fc_tls_set_verify(void *s, int mode, char *peer_cf)
{
}

static int
fc_tls_get_verify_result(void *s)
{
    return FC_OK;
}


