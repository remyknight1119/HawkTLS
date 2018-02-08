#include <stdio.h>
#include <string.h>

#include <falcontls/types.h>
#include <falcontls/crypto.h>
#include <falcontls/bio.h>

#include "internal/bio.h"

static int file_write(FC_BIO *h, const char *buf, int num);
static int file_read(FC_BIO *h, char *buf, int size);
static int file_puts(FC_BIO *h, const char *str);
static int file_gets(FC_BIO *h, char *str, int size);
static long file_ctrl(FC_BIO *h, int cmd, long arg1, void *arg2);
static int file_new(FC_BIO *h);
static int file_free(FC_BIO *data);

static const FC_BIO_METHOD methods_filep = {
    FC_BIO_TYPE_FILE,
    "FILE pointer",
    file_write,
    file_read,
    file_puts,
    file_gets,
    file_ctrl,
    file_new,
    file_free,
    NULL,
};

FC_BIO *FC_BIO_new_file(const char *filename, const char *mode)
{
    FC_BIO      *ret = NULL;
    FILE        *file = NULL;
    int         fp_flags = FC_BIO_CLOSE;

    file = fopen(filename, mode);
    if (file == NULL) {
        return (NULL);
    }

    if ((ret = FC_BIO_new(FC_BIO_s_file())) == NULL) {
        fclose(file);
        return (NULL);
    }

    FC_BIO_set_fp(ret, file, fp_flags);

    return (ret);
}

const FC_BIO_METHOD *FC_BIO_s_file(void)
{
    return (&methods_filep);
}

static int file_new(FC_BIO *bi)
{
    bi->b_init = 0;
    bi->b_num = 0;
    bi->b_ptr = NULL;
    
    return (1);
}

static int file_free(FC_BIO *a)
{
    if (a == NULL)
        return (0);

    if (a->b_shutdown) {
        if ((a->b_init) && (a->b_ptr != NULL)) {
            fclose(a->b_ptr);
            a->b_ptr = NULL;
        }
        a->b_init = 0;
    }
    return (1);
}

static int file_read(FC_BIO *b, char *out, int outl)
{
    int ret = 0;

    if (b->b_init && (out != NULL)) {
        ret = fread(out, 1, (int)outl, (FILE *)b->b_ptr);
        if (ret == 0 && ferror((FILE *)b->b_ptr)) {
            ret = -1;
        }
    }
    return (ret);
}

static int file_write(FC_BIO *b, const char *in, int inl)
{
    int ret = 0;

    if (b->b_init && (in != NULL)) {
        ret = fwrite(in, (int)inl, 1, (FILE *)b->b_ptr);
        if (ret) {
            ret = inl;
        }
        /*
         * according to Tim Hudson <tjh@cryptsoft.com>, the commented out
         * version above can cause 'inl' write calls under some stupid stdio
         * implementations (VMS)
         */
    }
    return (ret);
}

static long file_ctrl(FC_BIO *b, int cmd, long num, void *ptr)
{
    FILE    *fp = (FILE *)b->b_ptr;
    FILE    **fpp = NULL;
    char    p[4] = {};
    int     st = 0;
    long    ret = 1;

    switch (cmd) {
    case FC_BIO_C_FILE_SEEK:
    case FC_BIO_CTRL_RESET:
        ret = (long)fseek(fp, num, 0);
        break;
    case FC_BIO_CTRL_EOF:
        ret = (long)feof(fp);
        break;
    case FC_BIO_C_FILE_TELL:
    case FC_BIO_CTRL_INFO:
        ret = ftell(fp);
        break;
    case FC_BIO_C_SET_FILE_PTR:
        file_free(b);
        b->b_shutdown = (int)num & FC_BIO_CLOSE;
        b->b_ptr = ptr;
        b->b_init = 1;
        break;
    case FC_BIO_C_SET_FILENAME:
        file_free(b);
        b->b_shutdown = (int)num & FC_BIO_CLOSE;
        fp = fopen(ptr, p);
        if (fp == NULL) {
            ret = 0;
            break;
        }
        b->b_ptr = fp;
        b->b_init = 1;
        break;
    case FC_BIO_C_GET_FILE_PTR:
        /* the ptr parameter is actually a FILE ** in this case. */
        if (ptr != NULL) {
            fpp = (FILE **)ptr;
            *fpp = (FILE *)b->b_ptr;
        }
        break;
    case FC_BIO_CTRL_GET_CLOSE:
        ret = (long)b->b_shutdown;
        break;
    case FC_BIO_CTRL_SET_CLOSE:
        b->b_shutdown = (int)num;
        break;
    case FC_BIO_CTRL_FLUSH:
        st = fflush((FILE *)b->b_ptr);
        if (st == EOF) {
            ret = 0;
        }
        break;

    default:
        ret = 0;
        break;
    }

    return (ret);
}

static int file_gets(FC_BIO *bp, char *buf, int size)
{
    int ret = 0;

    buf[0] = '\0';
    if (!fgets(buf, size, (FILE *)bp->b_ptr)) {
        goto err;
    }

    if (buf[0] != '\0') {
        ret = strlen(buf);
    }

 err:
    return (ret);
}

static int file_puts(FC_BIO *bp, const char *str)
{
    return file_write(bp, str, strlen(str));
}


