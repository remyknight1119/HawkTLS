#ifndef __FC_BIO_H__
#define __FC_BIO_H__


extern FC_BIO *FC_BIO_new(const FC_BIO_METHOD *method);
extern int FC_BIO_free(FC_BIO *a);
extern int FC_BIO_read_filename(FC_BIO *b, const char *name);
extern void FC_BIO_set_data(FC_BIO *a, void *ptr);
extern void *FC_BIO_get_data(FC_BIO *a);
extern void FC_BIO_set_init(FC_BIO *a, int init);
extern int FC_BIO_get_init(FC_BIO *a);
extern void FC_BIO_set_shutdown(FC_BIO *a, int shut);
extern int FC_BIO_get_shutdown(FC_BIO *a);
extern void FC_BIO_vfree(FC_BIO *a);
extern int FC_BIO_read(FC_BIO *b, void *out, int outl);
extern int FC_BIO_write(FC_BIO *b, const void *in, int inl);
extern int FC_BIO_puts(FC_BIO *b, const char *in);
extern int FC_BIO_gets(FC_BIO *b, char *in, int inl);
extern long FC_BIO_ctrl(FC_BIO *b, int cmd, long larg, void *parg);
extern const FC_BIO_METHOD *FC_BIO_s_file(void);
extern FC_BIO *FC_BIO_new_file(const char *filename, const char *mode);
extern const FC_BIO_METHOD *FC_BIO_s_socket(void);
extern int FC_BIO_set_fd(FC_BIO *b, int fd, int flags);

#define FC_BIO_set_fp(b,fp,c)  FC_BIO_ctrl(b,FC_BIO_C_SET_FILE_PTR,c,(char *)fp)
#define FC_BIO_get_fp(b,fpp)   FC_BIO_ctrl(b,FC_BIO_C_GET_FILE_PTR,0,(char *)fpp)

#define FC_BIO_NOCLOSE          0x00
#define FC_BIO_CLOSE            0x01
#define FC_BIO_READ             0x02
#define FC_BIO_WRITE            0x04
#define FC_BIO_APPEND           0x08

#define FC_BIO_TYPE_FILE        1
#define FC_BIO_TYPE_SOCKET      2

enum {
    FC_BIO_C_RESET = 1,
    FC_BIO_C_EOF,
    FC_BIO_C_INFO,
    FC_BIO_C_FILE_SEEK,
    FC_BIO_C_FILE_TELL,
    FC_BIO_C_SET_FILE_PTR,
    FC_BIO_C_SET_FILENAME,
    FC_BIO_C_GET_FILE_PTR,
    FC_BIO_C_GET_CLOSE,
    FC_BIO_C_SET_CLOSE,
    FC_BIO_C_FLUSH,
    FC_BIO_C_SET_FD,
    FC_BIO_C_GET_FD,
    FC_BIO_C_DUP,
};
 
#endif
