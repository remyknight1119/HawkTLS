#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/epoll.h>

#include "dv_types.h"
#include "dv_lib.h"
#include "dv_errno.h"
#include "dv_ssl.h"
#include "dv_tls.h"
#include "ssl_test.h"

#define DV_DEF_IP_ADDRESS       "127.0.0.1"
#define DV_DEF_PORT             "7838"
#define DV_DEF_SERVER_CIPHERS   "ECDHE-RSA-AES128-GCM-SHA256"
#define DV_SERVER_LISTEN_NUM    5
#define DV_TEST_REQ             "Hello TLS!"
#define DV_TEST_RESP            "TLS OK!"
#define DV_TEST_EVENT_MAX_NUM   10
#define DV_TEST_CMD_START       "start"
#define DV_TEST_CMD_OK          "OK"
#define DV_TEST_CMD_END         "end"
#define DV_BUF_MAX_LEN          1000

static void dv_openssl_add_all_algorighms(void);
static void *dv_openssl_ctx_client_new(void);
static void *dv_openssl_ctx_server_new(void);
static int dv_openssl_ctx_use_certificate_file(void *ctx, const char *file);
static int dv_openssl_ctx_use_privateKey_file(void *ctx, const char *file);
static int dv_openssl_ctx_check_private_key(const void *ctx);
static int dv_openssl_ctx_set_ciphers(void *ctx);
static void *dv_openssl_new(void *ctx);
static int dv_openssl_set_fd(void *s, int fd);
static int dv_openssl_accept(void *s);
static int dv_openssl_connect(void *s);
static int dv_openssl_read(void *s, void *buf, int num);
static int dv_openssl_write(void *s, const void *buf, int num);
static int dv_openssl_shutdown(void *s);
static void dv_openssl_free(void *s);
static void dv_openssl_ctx_free(void *ctx);
static void dv_openssl_set_verify(void *s, int mode, char *peer_cf);
static int dv_openssl_get_verify_result(void *s);

static void *dv_dovessl_ctx_client_new(void);
static void *dv_dovessl_ctx_server_new(void);
static int dv_dovessl_ctx_use_certificate_file(void *ctx, const char *file);
static int dv_dovessl_ctx_use_privateKey_file(void *ctx, const char *file);
static int dv_dovessl_ctx_check_private_key(const void *ctx);
static int dv_dovessl_ctx_set_ciphers(void *ctx);
static void *dv_dovessl_new(void *ctx);
static int dv_dovessl_set_fd(void *s, int fd);
static int dv_dovessl_accept(void *s);
static int dv_dovessl_connect(void *s);
static int dv_dovessl_read(void *s, void *buf, int num);
static int dv_dovessl_write(void *s, const void *buf, int num);
static int dv_dovessl_shutdown(void *s);
static void dv_dovessl_free(void *s);
static void dv_dovessl_ctx_free(void *ctx);
static void dv_dovessl_set_verify(void *s, int mode, char *peer_cf);
static int dv_dovessl_get_verify_result(void *s);

static const char *
dv_program_version = "1.0.0";//PACKAGE_STRING;

static const struct option 
dv_long_opts[] = {
	{"help", 0, 0, 'H'},
	{"client", 0, 0, 'C'},
	{"server", 0, 0, 'S'},
	{"address", 0, 0, 'a'},
	{"port", 0, 0, 'p'},
	{"certificate", 0, 0, 'c'},
	{"key", 0, 0, 'k'},
	{0, 0, 0, 0}
};

static const char *
dv_options[] = {
	"--address      -a	IP address for SSL communication\n",	
	"--port         -p	Port for SSL communication\n",	
	"--certificate  -c	certificate file\n",	
	"--key          -k	private key file\n",	
	"--client       -C	Client use openssl lib\n",	
	"--server       -S	Server use openssl lib\n",	
	"--help         -H	Print help information\n",	
};

static const dv_proto_suite_t dv_openssl_suite = {
    .ps_verify_mode = SSL_VERIFY_PEER,
    .ps_library_init = SSL_library_init,
    .ps_add_all_algorithms = dv_openssl_add_all_algorighms,
    .ps_load_error_strings = SSL_load_error_strings,
    .ps_ctx_client_new = dv_openssl_ctx_client_new,
    .ps_ctx_server_new = dv_openssl_ctx_server_new,
    .ps_ctx_use_certificate_file = dv_openssl_ctx_use_certificate_file,
    .ps_ctx_use_privateKey_file = dv_openssl_ctx_use_privateKey_file,
    .ps_ctx_check_private_key = dv_openssl_ctx_check_private_key,
    .ps_ctx_set_ciphers = dv_openssl_ctx_set_ciphers,
    .ps_ssl_new = dv_openssl_new,
    .ps_set_fd = dv_openssl_set_fd,
    .ps_accept = dv_openssl_accept,
    .ps_connect = dv_openssl_connect,
    .ps_read = dv_openssl_read,
    .ps_write = dv_openssl_write,
    .ps_shutdown = dv_openssl_shutdown,
    .ps_ssl_free = dv_openssl_free,
    .ps_ctx_free = dv_openssl_ctx_free,
    .ps_set_verify = dv_openssl_set_verify,
    .ps_get_verify_result = dv_openssl_get_verify_result,
};

static const dv_proto_suite_t dv_dovessl_suite = {
    .ps_verify_mode = DV_SSL_VERIFY_PEER,
    .ps_library_init = dv_library_init,
    .ps_add_all_algorithms = dv_add_all_algorighms,
    .ps_load_error_strings = dv_load_error_strings,
    .ps_ctx_client_new = dv_dovessl_ctx_client_new,
    .ps_ctx_server_new = dv_dovessl_ctx_server_new,
    .ps_ctx_use_certificate_file = dv_dovessl_ctx_use_certificate_file,
    .ps_ctx_use_privateKey_file = dv_dovessl_ctx_use_privateKey_file,
    .ps_ctx_check_private_key = dv_dovessl_ctx_check_private_key,
    .ps_ctx_set_ciphers = dv_dovessl_ctx_set_ciphers,
    .ps_ssl_new = dv_dovessl_new,
    .ps_set_fd = dv_dovessl_set_fd,
    .ps_accept = dv_dovessl_accept,
    .ps_connect = dv_dovessl_connect,
    .ps_read = dv_dovessl_read,
    .ps_write = dv_dovessl_write,
    .ps_shutdown = dv_dovessl_shutdown,
    .ps_ssl_free = dv_dovessl_free,
    .ps_ctx_free = dv_dovessl_ctx_free,
    .ps_set_verify = dv_dovessl_set_verify,
    .ps_get_verify_result = dv_dovessl_get_verify_result,
};

static int
dv_openssl_callback(int ok, X509_STORE_CTX *ctx)
{
    return 1;
}

/* OpenSSL */
static void
dv_openssl_add_all_algorighms(void)
{
    OpenSSL_add_all_algorithms();
}

static void *
dv_openssl_ctx_client_new(void)
{
    return SSL_CTX_new(TLSv1_2_client_method());
}

static void *
dv_openssl_ctx_server_new(void)
{
    return SSL_CTX_new(TLSv1_2_server_method());
}

static int 
dv_openssl_ctx_use_certificate_file(void *ctx, const char *file)
{
    int     ret = 0;

    ret = SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
    if (ret <= 0) {
        return DV_ERROR;
    }

    return DV_OK;
}

static int
dv_openssl_ctx_use_privateKey_file(void *ctx, const char *file)
{
    int     ret = 0;

    ret = SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM);
    if (ret <= 0) {
        return DV_ERROR;
    }

    return DV_OK;
}

static int 
dv_openssl_ctx_set_ciphers(void *ctx)
{    
    int      nid = 0;
    EC_KEY  *ecdh = NULL;
    char    *name = "prime256v1";

    if (SSL_CTX_set_cipher_list(ctx, DV_DEF_SERVER_CIPHERS) == 0) {
        printf("Set cipher %s\n", DV_DEF_SERVER_CIPHERS);
        return DV_ERROR;
    }

    /*
     * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
     * from RFC 4492 section 5.1.1, or explicitly described curves over
     * binary fields. OpenSSL only supports the "named curves", which provide
     * maximum interoperability.
     */

    nid = OBJ_sn2nid((const char *)name);
    if (nid == 0) {
        printf("Nid error!\n");
        return DV_ERROR;
    }

    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == NULL) {
        printf("Unable to create curve \"%s\"", name);
        return DV_ERROR;
    }

    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);

    SSL_CTX_set_tmp_ecdh(ctx, ecdh);

    EC_KEY_free(ecdh);

    return DV_OK;
}

static int
dv_openssl_ctx_check_private_key(const void *ctx)
{
    int     ret = 0;

    ret = SSL_CTX_check_private_key(ctx);
    if (ret == 0) {
        return DV_ERROR;
    }

    return DV_OK;
}

static void *dv_openssl_new(void *ctx)
{
    return SSL_new(ctx);
}

static int
dv_openssl_set_fd(void *s, int fd)
{
    return SSL_set_fd(s, fd);
}

static int
dv_openssl_accept(void *s)
{
    return SSL_accept(s);
}

static int
dv_openssl_connect(void *s)
{
    return SSL_connect(s);
}

static int
dv_openssl_read(void *s, void *buf, int num)
{
    return SSL_read(s, buf, num);
}

static int
dv_openssl_write(void *s, const void *buf, int num)
{
    return SSL_write(s, buf, num);
}

static int
dv_openssl_shutdown(void *s)
{
    return SSL_shutdown(s);
}

static void
dv_openssl_free(void *s)
{
    SSL_free(s);
}

static void
dv_openssl_ctx_free(void *ctx)
{
    SSL_CTX_free(ctx);
}

static void 
dv_openssl_set_verify(void *ctx, int mode, char *peer_cf)
{
    STACK_OF(X509_NAME)  *list = NULL;

    SSL_CTX_set_verify(ctx, mode, dv_openssl_callback);
    SSL_CTX_set_verify_depth(ctx, 1);

    if (SSL_CTX_load_verify_locations(ctx, peer_cf, NULL) == 0) {
        fprintf(stderr, "Load verify locations %s failed\n", peer_cf);
        exit(1);
    }
    
    list = SSL_load_client_CA_file(peer_cf);
    if (list == NULL) {
        fprintf(stderr, "Load client ca file %s failed\n", peer_cf);
        exit(1);
    }

    SSL_CTX_set_client_CA_list(ctx, list);
}

static int
dv_openssl_get_verify_result(void *s)
{
    long    ret = 0;

    ret = SSL_get_verify_result(s);
    if (ret != X509_V_OK) {
        fprintf(stderr, "Verify ret is %ld\n", ret);
        return DV_ERROR;
    }

    return DV_OK;
}

/* DoveSSL */
static void *
dv_dovessl_ctx_client_new(void)
{
    return dv_ssl_ctx_new(dv_tls_v1_2_client_method());
}

static void *
dv_dovessl_ctx_server_new(void)
{
    return dv_ssl_ctx_new(dv_tls_v1_2_server_method());
}

static int 
dv_dovessl_ctx_use_certificate_file(void *ctx, const char *file)
{
    return dv_ssl_ctx_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
}

static int
dv_dovessl_ctx_use_privateKey_file(void *ctx, const char *file)
{
    return dv_ssl_ctx_use_private_key_file(ctx, file, SSL_FILETYPE_PEM);
}

static int
dv_dovessl_ctx_set_ciphers(void *ctx)
{
    return DV_OK;
}

static int
dv_dovessl_ctx_check_private_key(const void *ctx)
{
    return dv_ssl_ctx_check_private_key(ctx);
}

static void *
dv_dovessl_new(void *ctx)
{
    return dv_ssl_new(ctx);
}

static int
dv_dovessl_set_fd(void *s, int fd)
{
    return dv_ssl_set_fd(s, fd);
}

static int
dv_dovessl_accept(void *s)
{
    return dv_ssl_accept(s);
}

static int
dv_dovessl_connect(void *s)
{
    return dv_ssl_connect(s);
}

static int
dv_dovessl_read(void *s, void *buf, int num)
{
    return dv_ssl_read(s, buf, num);
}

static int
dv_dovessl_write(void *s, const void *buf, int num)
{
    return dv_ssl_write(s, buf, num);
}

static int
dv_dovessl_shutdown(void *s)
{
    return dv_ssl_shutdown(s);
}

static void
dv_dovessl_free(void *s)
{
    dv_ssl_free(s);
}

static void
dv_dovessl_ctx_free(void *ctx)
{
    dv_ssl_ctx_free(ctx);
}

static void 
dv_dovessl_set_verify(void *s, int mode, char *peer_cf)
{
}

static int
dv_dovessl_get_verify_result(void *s)
{
    return DV_OK;
}

static void
dv_add_epoll_event(int epfd, struct epoll_event *ev, int fd)
{
    ev->data.fd = fd;
    ev->events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev);
}

static int
dv_ssl_server_main(int pipefd, struct sockaddr_in *my_addr, char *cf,
        char *key, const dv_proto_suite_t *suite, char *peer_cf)
{
    struct epoll_event  ev = {};
    struct epoll_event  events[DV_TEST_EVENT_MAX_NUM] = {};
    int                 sockfd = 0;
    int                 efd = 0;
    int                 new_fd = 0;
    int                 epfd = 0;
    int                 nfds = 0;
    int                 reuse = 1;
    int                 i = 0;
    socklen_t           len = 0;
    ssize_t             rlen = 0;
    ssize_t             wlen = 0;
    struct sockaddr_in  their_addr = {};
    char                buf[DV_BUF_MAX_LEN] = {};
    void                *ctx = NULL;
    void                *ssl = NULL;
        
    /* SSL 库初始化 */
    suite->ps_library_init();
    /* 载入所有 SSL 算法 */
    suite->ps_add_all_algorithms();
    /* 载入所有 SSL 错误消息 */
    suite->ps_load_error_strings();
    /* 以 TLS1.2 标准兼容方式产生一个 SSL_CTX ,即 SSL Content Text */
    ctx = suite->ps_ctx_server_new();
    if (ctx == NULL) {
        fprintf(stderr, "CTX new failed!\n");
        exit(1);
    }
    /* 载入用户的数字证书, 此证书用来发送给客户端。 证书里包含有公钥 */
    if (suite->ps_ctx_use_certificate_file(ctx, cf) < 0) {
        fprintf(stderr, "Load certificate failed!\n");
        exit(1);
    }
    /* 载入用户私钥 */
    if (suite->ps_ctx_use_privateKey_file(ctx, key) < 0) {
        fprintf(stderr, "Load private key failed!\n");
        exit(1);
    }
    /* 检查用户私钥是否正确 */
    if (suite->ps_ctx_check_private_key(ctx) < 0) {
        fprintf(stderr, "Check private key failed!\n");
        exit(1);
    }
    suite->ps_set_verify(ctx, suite->ps_verify_mode, peer_cf);
    if (suite->ps_ctx_set_ciphers(ctx) != DV_OK) {
        fprintf(stderr, "Set cipher failed!\n");
        exit(1);
    }
    /* 开启一个 socket 监听 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (bind(sockfd, (struct sockaddr *)my_addr, sizeof(*my_addr)) == -1) {
        perror("bind");
        exit(1);
    }
    
    if (listen(sockfd, DV_SERVER_LISTEN_NUM) == -1) {
        perror("listen");
        exit(1);
    }

    epfd = epoll_create(1);
    if (epfd < 0) {
        exit(1);
    }
    dv_add_epoll_event(epfd, &ev, pipefd);
    dv_add_epoll_event(epfd, &ev, sockfd);

    while (1) {
        nfds = epoll_wait(epfd, events, DV_TEST_EVENT_MAX_NUM, -1);
        for (i = 0; i < nfds; i++) {
            if (events[i].events & EPOLLIN) {
                if ((efd = events[i].data.fd) < 0) {
                    continue;
                }

                /* Client有请求到达 */
                if (efd == sockfd) {
                    /* 等待客户端连上来 */
                    if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr,
                                    &len)) == -1) {
                        perror("accept");
                        exit(errno);
                    } 
                    /* 基于 ctx 产生一个新的 SSL */
                    ssl = suite->ps_ssl_new(ctx);
                    /* 将连接用户的 socket 加入到 SSL */
                    suite->ps_set_fd(ssl, new_fd);
                    /* 建立 SSL 连接 */
                    if (suite->ps_accept(ssl) == -1) {
                        perror("accept");
                        close(new_fd);
                        goto out;
                    }
                    if (suite->ps_get_verify_result(ssl) != DV_OK) {
                        printf("Client cert verify failed!\n");
                        exit(1);
                    }
                    /* 开始处理每个新连接上的数据收发 */
                    bzero(buf, sizeof(buf));
                    /* 接收客户端的消息 */
                    len = suite->ps_read(ssl, buf, sizeof(buf));
                    if (len > 0 && strcmp(buf, DV_TEST_REQ) == 0) {
                        printf("Server接收消息成功:'%s',共%d 个字节的数据\n",
                                buf, len);
                    } else {
                        printf("Server消息接收失败!错误代码是%d,错误信息是'%s'\n",
                             errno, strerror(errno));
                        exit(1);
                    }
                    /* 发消息给客户端 */
                    len = suite->ps_write(ssl, DV_TEST_RESP, sizeof(DV_TEST_RESP));
                    if (len <= 0) {
                        printf("Server消息'%s'发送失败!错误信息是'%s'\n",
                             buf, strerror(errno));
                        exit(1);
                    } 
                    printf("Server消息'%s'发送成功,共发送了%d 个字节!\n",
                            DV_TEST_RESP, len);

                    /* 处理每个新连接上的数据收发结束 */
                    /* 关闭 SSL 连接 */
                    suite->ps_shutdown(ssl);
                    /* 释放 SSL */
                    suite->ps_ssl_free(ssl);
                    /* 关闭 socket */
                    close(new_fd);
                    dv_add_epoll_event(epfd, &ev, sockfd);
                    continue;
                }
                if (efd == pipefd) {
                    rlen = read(pipefd, buf, sizeof(buf));
                    if (rlen < 0) {
                        fprintf(stderr, "Read form pipe failed!\n");
                        goto out;
                    }
                    wlen = write(pipefd, DV_TEST_CMD_OK, sizeof(DV_TEST_CMD_OK));
                    if (wlen < sizeof(DV_TEST_CMD_OK)) {
                        fprintf(stderr, "Write to pipe failed!\n");
                        goto out;
                    }
                    if (strcmp(buf, DV_TEST_CMD_START) == 0) {
                        fprintf(stdout, "Test start!\n");
                        dv_add_epoll_event(epfd, &ev, sockfd);
                    } else {
                        goto out;
                    }
                }
            }
        }
    }
out:
    close(epfd);
    /* 关闭监听的 socket */
    close(sockfd);
    /* 释放 CTX */
    suite->ps_ctx_free(ctx);
    fprintf(stdout, "Server exit!\n");
    exit(0);
}

static int
dv_ssl_server(int pipefd, struct sockaddr_in *addr, char *cf,
        char *key, const dv_proto_suite_t *suite, char *peer_cf)
{
    return dv_ssl_server_main(pipefd, addr, cf, key, suite, peer_cf);
}

#if 0
void ShowCerts(SSL * ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    } else
        printf("无证书信息!\n");
}
#endif

static int 
dv_ssl_client_main(struct sockaddr_in *dest, char *cf, char *key,
        const dv_proto_suite_t *suite, char *peer_cf)
{
    int         sockfd = 0;
    int         len = 0;
    char        buffer[DV_BUF_MAX_LEN] = {};
    SSL_CTX     *ctx = NULL;
    SSL         *ssl = NULL;
    int         ret = DV_OK;

    suite->ps_library_init();
    suite->ps_add_all_algorithms();
    suite->ps_load_error_strings();
    ctx = suite->ps_ctx_client_new();
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        return DV_ERROR;
    }

    /* 载入用户的数字证书, 此证书用来发送给客户端。 证书里包含有公钥 */
    if (suite->ps_ctx_use_certificate_file(ctx, cf) < 0) {
        fprintf(stderr, "Load certificate %s failed!\n", cf);
        exit(1);
    }
    /* 载入用户私钥 */
    if (suite->ps_ctx_use_privateKey_file(ctx, key) < 0) {
        fprintf(stderr, "Load private key %s failed!\n", key);
        exit(1);
    }
    /* 检查用户私钥是否正确 */
    if (suite->ps_ctx_check_private_key(ctx) < 0) {
        fprintf(stderr, "Check private key failed!\n");
        exit(1);
    }
 
    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");
    printf("address created\n");
    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *)dest, sizeof(*dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");
    suite->ps_set_verify(ctx, suite->ps_verify_mode, peer_cf);
    /* 基于 ctx 产生一个新的 SSL */
    ssl = suite->ps_ssl_new(ctx);
    suite->ps_set_fd(ssl, sockfd);
    /* 建立 SSL 连接 */
    if (suite->ps_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
    } else {
        //printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        //ShowCerts(ssl);
    }

    if (suite->ps_get_verify_result(ssl) != DV_OK) {
        printf("Server cert verify failed!\n");
        exit(1);
    }
    /* 发消息给服务器 */
    len = suite->ps_write(ssl, DV_TEST_REQ, sizeof(DV_TEST_REQ));
    if (len < 0) {
        printf("Client消息'%s'发送失败!错误代码是%d,错误信息是'%s'\n",
             buffer, errno, strerror(errno));
        exit(1);
    } else {
        printf("Client消息'%s'发送成功,共发送了%d 个字节!\n",
                DV_TEST_REQ, len);
    }

    /* 接收服务器来的消息 */
    len = suite->ps_read(ssl, buffer, sizeof(buffer));
    if (len > 0 && strcmp(buffer, DV_TEST_RESP) == 0) {
        printf("Client接收消息成功:'%s',共%d 个字节的数据\n",
                buffer, len);
    } else {
        printf("Client消息接收失败!错误代码是%d,错误信息是'%s', len = %d\n",
             errno, strerror(errno), len);
        ret = DV_ERROR;
    }

    /* 关闭连接 */
    suite->ps_shutdown(ssl);
    suite->ps_ssl_free(ssl);
    close(sockfd);
    suite->ps_ctx_free(ctx);
    return ret;
}

static int
dv_ssl_client(int pipefd, struct sockaddr_in *addr, char *cf, 
        char *key, const dv_proto_suite_t *suite, char *peer_cf)
{
    char                buf[DV_BUF_MAX_LEN] = {};
    ssize_t             rlen = 0;
    ssize_t             wlen = 0;
    int                 ret = 0;

    wlen = write(pipefd, DV_TEST_CMD_START, strlen(DV_TEST_CMD_START));
    if (wlen < strlen(DV_TEST_CMD_START)) {
        fprintf(stderr, "Write to pipefd failed(errno=%s)\n", strerror(errno));
        return DV_ERROR;
    }
    rlen = read(pipefd, buf, sizeof(buf));
    if (rlen < 0 || strcmp(DV_TEST_CMD_OK, buf) != 0) {
        fprintf(stderr, "Read from pipefd failed(errno=%s)\n", strerror(errno));
        return DV_ERROR;
    }
    ret = dv_ssl_client_main(addr, cf, key, suite, peer_cf);
    if (ret != DV_OK) {
        close(pipefd);
        return DV_ERROR;
    }

    wlen = write(pipefd, DV_TEST_CMD_END, strlen(DV_TEST_CMD_END));
    if (wlen < strlen(DV_TEST_CMD_END)) {
        fprintf(stderr, "Write to pipefd failed(errno=%s), wlen = %d\n",
                strerror(errno), (int)wlen);
        close(pipefd);
        return DV_ERROR;
    }

    rlen = read(pipefd, buf, sizeof(buf));
    close(pipefd);
    if (rlen < 0 || strcmp(DV_TEST_CMD_OK, buf) != 0) {
        fprintf(stderr, "Read from pipefd failed(errno=%s)\n", strerror(errno));
        return DV_ERROR;
    }
    return DV_OK;
}

static void 
dv_help(void)
{
	int     index;

	fprintf(stdout, "Version: %s\n", dv_program_version);

	fprintf(stdout, "\nOptions:\n");
	for(index = 0; index < DV_ARRAY_SIZE(dv_options); index++) {
		fprintf(stdout, "  %s", dv_options[index]);
	}
}

static const char *
dv_optstring = "HCSa:p:c:k:";

int
main(int argc, char **argv)  
{
    int                     c = 0;
    int                     fd[2] = {};
    struct sockaddr_in      addr = {
        .sin_family = AF_INET,
    };
    pid_t                   pid = 0;
    dv_u16                  pport = 0;
    const dv_proto_suite_t  *client_suite = &dv_dovessl_suite;
    const dv_proto_suite_t  *server_suite = &dv_dovessl_suite;
    char                    *ip = DV_DEF_IP_ADDRESS;
    char                    *port = DV_DEF_PORT;
    char                    *cf = NULL;
    char                    *key = NULL;
    char                    *client_cf = NULL;
    char                    *client_key = NULL;

    while((c = getopt_long(argc, argv, 
                    dv_optstring,  dv_long_opts, NULL)) != -1) {
        switch(c) {
            case 'H':
                dv_help();
                return DV_OK;

            case 'C':
                client_suite = &dv_openssl_suite;
                break;

            case 'S':
                server_suite = &dv_openssl_suite;
                break;

            case 'a':
                ip = optarg;
                break;

            case 'p':
                port = optarg;
                break;

            case 'c':
                cf = optarg;
                break;

            case 'k':
                key = optarg;
                break;

            default:
                dv_help();
                return -DV_ERROR;
        }
    }

    if (cf == NULL) {
        fprintf(stderr, "Please input cf by -c!\n");
        return -DV_ERROR;
    }

    if (key == NULL) {
        fprintf(stderr, "Please input key by -k!\n");
        return -DV_ERROR;
    }

    pport = atoi(port);
    addr.sin_port = htons(pport);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
        fprintf(stderr, "Create socketpair failed(errn=%s)!\n",
                strerror(errno));
        return -DV_ERROR;
    }

    if ((pid = fork()) < 0) {
        fprintf(stderr, "Fork failed!\n");
        return -DV_ERROR;
    }

    client_cf = strstr(cf, ",");
    if (client_cf == NULL) {
        fprintf(stderr, "Client certificate not set!\n");
        return -DV_ERROR;
    }
    *client_cf++ = 0;
    client_key = strstr(key, ",");
    if (client_key == NULL) {
        fprintf(stderr, "Client key not set!\n");
        return -DV_ERROR;
    }
    *client_key++ = 0;

    if (pid > 0) {  /* Parent */
        close(fd[0]);
        return -dv_ssl_client(fd[1], &addr, client_cf, client_key, 
                client_suite, cf);
    }

    /* Child */
    close(fd[1]);
    return -dv_ssl_server(fd[0], &addr, cf, key, server_suite, client_cf);
}
