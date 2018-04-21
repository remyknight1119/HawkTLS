#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <falcontls/types.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>

#include "internal/bio.h"

static int sock_write(FC_BIO *h, const char *buf, int num);
static int sock_read(FC_BIO *h, char *buf, int size);
static int sock_puts(FC_BIO *h, const char *str);
static long sock_ctrl(FC_BIO *h, int cmd, long arg1, void *arg2);
static int sock_new(FC_BIO *h);
static int sock_free(FC_BIO *data);
int FC_BIO_sock_should_retry(int s);

static const FC_BIO_METHOD methods_sockp = {
    .bm_type = FC_BIO_TYPE_SOCKET,
    .bm_name = "socket",
    .bm_write = sock_write,
    .bm_read = sock_read,
    .bm_puts = sock_puts,
    .bm_ctrl = sock_ctrl,
    .bm_create = sock_new,
    .bm_destroy = sock_free,
};

const FC_BIO_METHOD *
FC_BIO_s_socket(void)
{
    return (&methods_sockp);
}

FC_BIO *
FC_BIO_new_socket(int fd, int close_flag)
{
    FC_BIO *ret;

    ret = FC_BIO_new(FC_BIO_s_socket());
    if (ret == NULL)
        return (NULL);
    FC_BIO_set_fd(ret, fd, close_flag);
    return (ret);
}

static int
sock_new(FC_BIO *bi)
{
    bi->b_init = 0;
    bi->b_num = 0;
    bi->b_ptr = NULL;
    bi->b_flags = 0;

    return (1);
}

static int
sock_free(FC_BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->b_shutdown) {
        if (a->b_init) {
            close(a->b_num);
        }
        a->b_init = 0;
        a->b_flags = 0;
    }
    return (1);
}

static int
sock_read(FC_BIO *b, char *out, int outl)
{
    return recv(b->b_num, out, outl, 0);
}

static int
sock_write(FC_BIO *b, const char *in, int inl)
{
    return send(b->b_num, in, inl, 0);
}

static long
sock_ctrl(FC_BIO *b, int cmd, long num, void *ptr)
{
    long    ret = 1;
    int     *ip = NULL;

    switch (cmd) {
    case FC_BIO_C_SET_FD:
        sock_free(b);
        b->b_num = *((int *)ptr);
        b->b_shutdown = (int)num;
        b->b_init = 1;
        break;
    case FC_BIO_C_GET_FD:
        if (b->b_init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = b->b_num;
            ret = b->b_num;
        } else {
            ret = -1;
        }
        break;
    case FC_BIO_C_GET_CLOSE:
        ret = b->b_shutdown;
        break;
    case FC_BIO_C_SET_CLOSE:
        b->b_shutdown = (int)num;
        break;
    case FC_BIO_C_DUP:
    case FC_BIO_C_FLUSH:
        ret = 1;
        break;
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int
sock_puts(FC_BIO *bp, const char *str)
{
    return sock_write(bp, str, strlen(str));
}

int FC_BIO_sock_non_fatal_error(int err)
{
    switch (err) {
    case ENOTCONN:
    case EINTR:
    case EAGAIN:
    case EPROTO:
    case EINPROGRESS:
    case EALREADY:
        return (1);
    default:
        break;
    }
    return (0);
}

