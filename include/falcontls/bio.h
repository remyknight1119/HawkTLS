#ifndef __FC_BIO_H__
#define __FC_BIO_H__

#ifdef FC_OPENSSL
#include <openssl/bio.h>

#define FC_BIO_new BIO_new
#define FC_BIO_s_file BIO_s_file
#define FC_BIO_read_filename BIO_read_filename
#define FC_BIO_free BIO_free
#else //FC_BIO_OPENSSL

extern FC_BIO *FC_BIO_new(const FC_BIO_METHOD *method);
extern int FC_BIO_free(FC_BIO *a);
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

#define FC_BIO_set_fp(b,fp,c)  FC_BIO_ctrl(b,FC_BIO_C_SET_FILE_PTR,c,(char *)fp)
#define FC_BIO_get_fp(b,fpp)   FC_BIO_ctrl(b,FC_BIO_C_GET_FILE_PTR,0,(char *)fpp)

#define FC_BIO_CLOSE            0x01

#define FC_BIO_TYPE_FILE        1
#define FC_BIO_TYPE_SOCKET      2

#define FC_BIO_C_FILE_SEEK      10
#define FC_BIO_CTRL_RESET       11
#define FC_BIO_CTRL_EOF         12
#define FC_BIO_C_FILE_TELL      13
#define FC_BIO_CTRL_INFO        14
#define FC_BIO_C_SET_FILE_PTR   15
#define FC_BIO_C_SET_FILENAME   16
#define FC_BIO_C_GET_FILE_PTR   17
#define FC_BIO_CTRL_GET_CLOSE   18
#define FC_BIO_CTRL_SET_CLOSE   19
#define FC_BIO_CTRL_FLUSH       20
#endif //FC_BIO_OPENSSL
 
#endif
