#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <errno.h>
#include <arpa/inet.h>

#include <falcontls/types.h>
#include <fc_log.h>

#include "tls_test.h"

#define FC_DEF_IP_ADDRESS       "127.0.0.1"
#define FC_DEF_PORT             "448"
#define FC_SERVER_LISTEN_NUM    5
#define FC_TEST_REQ             "Hello TLS!"
#define FC_TEST_RESP            "TLS OK!"
#define FC_TEST_EVENT_MAX_NUM   10
#define FC_TEST_CMD_START       "start"
#define FC_TEST_CMD_OK          "OK"
#define FC_TEST_CMD_END         "end"
#define FC_BUF_MAX_LEN          1000

#define FC_TLS_TYPE_FALCONTLS       1
#define FC_TLS_TYPE_OPENSSL         2

static const char *
fc_program_version = "1.0.0";//PACKAGE_STRING;

static const struct option 
fc_long_opts[] = {
	{"help", 0, 0, 'H'},
	{"client", 0, 0, 'C'},
	{"server", 0, 0, 'S'},
	{"port", 0, 0, 'p'},
	{"certificate", 0, 0, 'c'},
	{"key", 0, 0, 'k'},
	{0, 0, 0, 0}
};

static const char *
fc_options[] = {
	"--port         -p	Port for TLS communication\n",	
	"--certificate  -c	certificate file\n",	
	"--key          -k	private key file\n",	
	"--client       -C	Client use openssl lib\n",	
	"--server       -S	Server use openssl lib\n",	
	"--help         -H	Print help information\n",	
};

static void
fc_add_epoll_event(int epfd, struct epoll_event *ev, int fd)
{
    ev->data.fd = fd;
    ev->events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev);
}

static int
fc_ssl_server_main(int pipefd, struct sockaddr_in *my_addr, char *cf,
        char *key, const PROTO_SUITE *suite, char *peer_cf)
{
    void                *ctx = NULL;
    void                *ssl = NULL;
    struct epoll_event  ev = {};
    struct epoll_event  events[FC_TEST_EVENT_MAX_NUM] = {};
    struct sockaddr_in  their_addr = {};
    char                buf[FC_BUF_MAX_LEN] = {};
    socklen_t           len = 0;
    ssize_t             rlen = 0;
    ssize_t             wlen = 0;
    int                 sockfd = 0;
    int                 efd = 0;
    int                 new_fd = 0;
    int                 epfd = 0;
    int                 nfds = 0;
    int                 reuse = 1;
    int                 i = 0;
        
    /* TLS 库初始化 */
    suite->ps_library_init();
    /* 载入所有 TLS 算法 */
    suite->ps_add_all_algorithms();
    /* 载入所有 TLS 错误消息 */
    suite->ps_load_error_strings();
    /* 以 TLS1.2 标准兼容方式产生一个 TLS_CTX ,即 TLS Content Text */
    ctx = suite->ps_ctx_server_new();
    if (ctx == NULL) {
        FC_LOG("CTX new failed!\n");
        exit(1);
    }
    /* 载入用户的数字证书, 此证书用来发送给客户端。 证书里包含有公钥 */
    if (suite->ps_ctx_use_certificate_file(ctx, cf) < 0) {
        FC_LOG("Load certificate failed!\n");
        exit(1);
    }
    /* 载入用户私钥 */
    if (suite->ps_ctx_use_privateKey_file(ctx, key) < 0) {
        FC_LOG("Load private key failed!\n");
        exit(1);
    }
    /* 检查用户私钥是否正确 */
    if (suite->ps_ctx_check_private_key(ctx) < 0) {
        FC_LOG("Check private key failed!\n");
        exit(1);
    }
    suite->ps_set_verify(ctx, suite->ps_verify_mode, peer_cf);
    if (suite->ps_ctx_set_ciphers(ctx) != FC_OK) {
        FC_LOG("Set cipher failed!\n");
        exit(1);
    }
    /* 开启一个 socket 监听 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        FC_LOG("socket failed!\n");
        exit(1);
    }

    FC_LOG("server!\n");
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (bind(sockfd, (struct sockaddr *)my_addr, sizeof(*my_addr)) == -1) {
        perror("bind");
        exit(1);
    }
    
    if (listen(sockfd, FC_SERVER_LISTEN_NUM) == -1) {
        perror("listen");
        exit(1);
    }

    epfd = epoll_create(1);
    if (epfd < 0) {
        exit(1);
    }
    fc_add_epoll_event(epfd, &ev, pipefd);
    fc_add_epoll_event(epfd, &ev, sockfd);

    while (1) {
        nfds = epoll_wait(epfd, events, FC_TEST_EVENT_MAX_NUM, -1);
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
                    /* 基于 ctx 产生一个新的 TLS */
                    ssl = suite->ps_ssl_new(ctx);
                    /* 将连接用户的 socket 加入到 TLS */
                    suite->ps_set_fd(ssl, new_fd);
                    /* 建立 TLS 连接 */
                    if (suite->ps_accept(ssl) == -1) {
                        perror("accept");
                        close(new_fd);
                        goto out;
                    }
                    if (suite->ps_get_verify_result(ssl) != FC_OK) {
                        FC_LOG("Client cert verify failed!\n");
                        exit(1);
                    }
                    /* 开始处理每个新连接上的数据收发 */
                    bzero(buf, sizeof(buf));
                    /* 接收客户端的消息 */
                    len = suite->ps_read(ssl, buf, sizeof(buf));
                    if (len > 0 && strcmp(buf, FC_TEST_REQ) == 0) {
                        FC_LOG("Server接收消息成功:'%s',共%d 个字节的数据\n",
                                buf, len);
                    } else {
                        FC_LOG("Server消息接收失败!错误代码是%d,错误信息是'%s'\n",
                             errno, strerror(errno));
                        exit(1);
                    }
                    /* 发消息给客户端 */
                    len = suite->ps_write(ssl, FC_TEST_RESP, sizeof(FC_TEST_RESP));
                    if (len <= 0) {
                        FC_LOG("Server消息'%s'发送失败!错误信息是'%s'\n",
                             buf, strerror(errno));
                        exit(1);
                    } 
                    FC_LOG("Server消息'%s'发送成功,共发送了%d 个字节!\n",
                            FC_TEST_RESP, len);

                    /* 处理每个新连接上的数据收发结束 */
                    /* 关闭 TLS 连接 */
                    suite->ps_shutdown(ssl);
                    /* 释放 TLS */
                    suite->ps_ssl_free(ssl);
                    /* 关闭 socket */
                    close(new_fd);
                    fc_add_epoll_event(epfd, &ev, sockfd);
                    continue;
                }
                if (efd == pipefd) {
                    rlen = read(pipefd, buf, sizeof(buf));
                    if (rlen < 0) {
                        FC_LOG("Read form pipe failed!\n");
                        goto out;
                    }
                    wlen = write(pipefd, FC_TEST_CMD_OK, sizeof(FC_TEST_CMD_OK));
                    if (wlen < sizeof(FC_TEST_CMD_OK)) {
                        FC_LOG("Write to pipe failed!\n");
                        goto out;
                    }
                    if (strcmp(buf, FC_TEST_CMD_START) == 0) {
                        fprintf(stdout, "Test start!\n");
                        fc_add_epoll_event(epfd, &ev, sockfd);
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
fc_ssl_server(int pipefd, struct sockaddr_in *addr, char *cf,
        char *key, const PROTO_SUITE *suite, char *peer_cf)
{
    return fc_ssl_server_main(pipefd, addr, cf, key, suite, peer_cf);
}

#if 0
void ShowCerts(TLS * ssl)
{
    X509 *cert;
    char *line;
    cert = TLS_get_peer_certificate(ssl);
    if (cert != NULL) {
        FC_LOG("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        FC_LOG("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        FC_LOG("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    } else
        FC_LOG("无证书信息!\n");
}
#endif

static int 
fc_ssl_client_main(struct sockaddr_in *dest, char *cf, char *key,
        const PROTO_SUITE *suite, char *peer_cf)
{
    int         sockfd = 0;
    int         len = 0;
    char        buffer[FC_BUF_MAX_LEN] = {};
    TLS_CTX     *ctx = NULL;
    TLS         *ssl = NULL;
    int         ret = FC_OK;

    suite->ps_library_init();
    suite->ps_add_all_algorithms();
    suite->ps_load_error_strings();
    ctx = suite->ps_ctx_client_new();
    if (ctx == NULL) {
        return FC_ERROR;
    }

    /* 载入用户的数字证书, 此证书用来发送给客户端。 证书里包含有公钥 */
    if (suite->ps_ctx_use_certificate_file(ctx, cf) < 0) {
        FC_LOG("Load certificate %s failed!\n", cf);
        exit(1);
    }

    /* 载入用户私钥 */
    if (suite->ps_ctx_use_privateKey_file(ctx, key) < 0) {
        FC_LOG("Load private key %s failed!\n", key);
        exit(1);
    }

#if 0
    /* 检查用户私钥是否正确 */
    if (suite->ps_ctx_check_private_key(ctx) < 0) {
        FC_LOG("Check private key failed!\n");
        //exit(1);
    }
#endif

    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    FC_LOG("socket created\n");
    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *)dest, sizeof(*dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    FC_LOG("server connected\n");
    suite->ps_set_verify(ctx, suite->ps_verify_mode, peer_cf);
    /* 基于 ctx 产生一个新的 TLS */
    ssl = suite->ps_ssl_new(ctx);
    suite->ps_set_fd(ssl, sockfd);
    /* 建立 TLS 连接 */
    if (suite->ps_connect(ssl) == FC_ERROR) {
        FC_LOG("Client connect failed!\n");
        exit(1);
    } 
    //printf("Connected with %s encryption\n", TLS_get_cipher(ssl));
    //ShowCerts(ssl);

    if (suite->ps_get_verify_result(ssl) != FC_OK) {
        FC_LOG("Server cert verify failed!\n");
        exit(1);
    }
    /* 发消息给服务器 */
    len = suite->ps_write(ssl, FC_TEST_REQ, sizeof(FC_TEST_REQ));
    if (len < 0) {
        FC_LOG("Client消息'%s'发送失败!错误代码是%d,错误信息是'%s'\n",
             buffer, errno, strerror(errno));
        exit(1);
    }
    FC_LOG("Client消息'%s'发送成功,共发送了%d 个字节!\n",
            FC_TEST_REQ, len);

    /* 接收服务器来的消息 */
    len = suite->ps_read(ssl, buffer, sizeof(buffer));
    if (len > 0 && strcmp(buffer, FC_TEST_RESP) == 0) {
        FC_LOG("Client接收消息成功:'%s',共%d 个字节的数据\n",
                buffer, len);
    } else {
        FC_LOG("Client消息接收失败!错误代码是%d,错误信息是'%s', len = %d\n",
             errno, strerror(errno), len);
        ret = FC_ERROR;
    }

    /* 关闭连接 */
    suite->ps_shutdown(ssl);
    suite->ps_ssl_free(ssl);
    close(sockfd);
    suite->ps_ctx_free(ctx);
    return ret;
}

static int
fc_ssl_client(int pipefd, struct sockaddr_in *addr, char *cf, 
        char *key, const PROTO_SUITE *suite, char *peer_cf)
{
    char                buf[FC_BUF_MAX_LEN] = {};
    ssize_t             rlen = 0;
    ssize_t             wlen = 0;
    int                 ret = 0;

    wlen = write(pipefd, FC_TEST_CMD_START, strlen(FC_TEST_CMD_START));
    if (wlen < strlen(FC_TEST_CMD_START)) {
        FC_LOG("Write to pipefd failed(errno=%s)\n", strerror(errno));
        return FC_ERROR;
    }
    rlen = read(pipefd, buf, sizeof(buf));
    if (rlen < 0 || strcmp(FC_TEST_CMD_OK, buf) != 0) {
        FC_LOG("Read from pipefd failed(errno=%s)\n", strerror(errno));
        return FC_ERROR;
    }
    ret = fc_ssl_client_main(addr, cf, key, suite, peer_cf);
    if (ret != FC_OK) {
        close(pipefd);
        return FC_ERROR;
    }

    wlen = write(pipefd, FC_TEST_CMD_END, strlen(FC_TEST_CMD_END));
    if (wlen < strlen(FC_TEST_CMD_END)) {
        FC_LOG("Write to pipefd failed(errno=%s), wlen = %d\n",
                strerror(errno), (int)wlen);
        close(pipefd);
        return FC_ERROR;
    }

    rlen = read(pipefd, buf, sizeof(buf));
    close(pipefd);
    if (rlen < 0 || strcmp(FC_TEST_CMD_OK, buf) != 0) {
        FC_LOG("Read from pipefd failed(errno=%s)\n", strerror(errno));
        return FC_ERROR;
    }
    return FC_OK;
}

static void 
fc_help(void)
{
	int     index;

	fprintf(stdout, "Version: %s\n", fc_program_version);

	fprintf(stdout, "\nOptions:\n");
	for(index = 0; index < FC_ARRAY_SIZE(fc_options); index++) {
		fprintf(stdout, "  %s", fc_options[index]);
	}
}

static const char *
fc_optstring = "HCSp:c:k:";

int
main(int argc, char **argv)  
{
    int                     c = 0;
    int                     fd[2] = {};
    struct sockaddr_in      addr = {
        .sin_family = AF_INET,
    };
    pid_t                   pid = 0;
    fc_u16                  pport = 0;
    const PROTO_SUITE       *client_suite = &fc_tls_suite;
    const PROTO_SUITE       *server_suite = &fc_tls_suite;
    char                    *ip = FC_DEF_IP_ADDRESS;
    char                    *port = FC_DEF_PORT;
    char                    *cf = NULL;
    char                    *key = NULL;
    char                    *client_cf = NULL;
    char                    *client_key = NULL;

    while ((c = getopt_long(argc, argv, fc_optstring, 
                    fc_long_opts, NULL)) != -1) {
        switch(c) {
            case 'H':
                fc_help();
                return FC_OK;

            case 'C':
                client_suite = &fc_openssl_suite;
                break;

            case 'S':
                server_suite = &fc_openssl_suite;
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
                fc_help();
                return -FC_ERROR;
        }
    }

    if (cf == NULL) {
        FC_LOG("Please input cf by -c!\n");
        return -FC_ERROR;
    }

    if (key == NULL) {
        FC_LOG("Please input key by -k!\n");
        return -FC_ERROR;
    }

    pport = atoi(port);
    addr.sin_port = htons(pport);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
        FC_LOG("Create socketpair failed(errn=%s)!\n",
                strerror(errno));
        return -FC_ERROR;
    }

    if ((pid = fork()) < 0) {
        FC_LOG("Fork failed!\n");
        return -FC_ERROR;
    }

    client_cf = strstr(cf, ",");
    if (client_cf == NULL) {
        FC_LOG("Client certificate not set!\n");
        return -FC_ERROR;
    }
    *client_cf++ = 0;
    client_key = strstr(key, ",");
    if (client_key == NULL) {
        FC_LOG("Client key not set!\n");
        return -FC_ERROR;
    }
    *client_key++ = 0;

    if (pid > 0) {  /* Parent */
        close(fd[0]);
        return -fc_ssl_client(fd[1], &addr, client_cf, client_key, 
                client_suite, cf);
    }

    /* Child */
    close(fd[1]);
    return -fc_ssl_server(fd[0], &addr, cf, key, server_suite, client_cf);
}
