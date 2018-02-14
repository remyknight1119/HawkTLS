#ifndef __FC_TLS_LOCL_H__
#define __FC_TLS_LOCL_H__

#include <falcontls/tls.h>
#include <falcontls/types.h>
#include <falcontls/evp.h>
#include <falcontls/safestack.h>

#include "statem.h"
#include "record_locl.h"

#define TLS_HM_HEADER_LENGTH                4

#define TLS_RT_CHANGE_CIPHER_SPEC           20
#define TLS_RT_ALERT                        21
#define TLS_RT_HANDSHAKE                    22
#define TLS_RT_APPLICATION_DATA             23

#define TLS_HANDSHAKE_TYPE_HELLO_REQUEST        0
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO         1
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO         2
#define TLS_HANDSHAKE_TYPE_SESSION_TICKET       4
#define TLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST  6
#define TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS 8
#define TLS_HANDSHAKE_TYPE_CERTIFICATE          11
#define TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE  12
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST  13
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE    14
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY   15
#define TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE  16
#define TLS_HANDSHAKE_TYPE_SERVER_CONFIGURATION 17
#define TLS_HANDSHAKE_TYPE_FINISHED             20
#define TLS_HANDSHAKE_TYPE_KEY_UPDATE           24

typedef enum {
    TLS_NOTHING = 1,
    TLS_WRITING,
    TLS_READING,
    TLS_X509_LOOKUP,
    TLS_ASYNC_PAUSED,
    TLS_ASYNC_NO_JOBS,
} TLS_RWSTATE;

/* These will only be used when doing non-blocking IO */
#define TLS_want_nothing(s)     (TLS_want(s) == TLS_NOTHING)
#define TLS_want_read(s)        (TLS_want(s) == TLS_READING)
#define TLS_want_write(s)       (TLS_want(s) == TLS_WRITING)
#define TLS_want_x509_lookup(s) (TLS_want(s) == TLS_X509_LOOKUP)
#define TLS_want_async(s)       (TLS_want(s) == TLS_ASYNC_PAUSED)
#define TLS_want_async_job(s)   (TLS_want(s) == TLS_ASYNC_NO_JOBS)

typedef struct tls_cert_pkey_t {
    FC_X509                 *cp_x509;
    FC_EVP_PKEY             *cp_privatekey;
    FC_STACK_OF(FC_X509)    *cp_chain;
} CERT_PKEY;

typedef struct tls_cert_t {
    CERT_PKEY           *ct_key;
    CERT_PKEY           ct_pkeys[FC_EVP_PKEY_NUM];
} CERT;

struct fc_tls_t {
    TLS_STATEM          tls_statem;
    bool                tls_server;
    bool                tls_shutdown;
    int                 tls_fd;
    const TLS_METHOD    *tls_method;
    TLS_CTX             *tls_ctx;
    CERT                *tls_cert;
    FC_BIO              *tls_rbio;
    FC_BIO              *tls_wbio;
    FC_BUF_MEM          *tls_init_buf;
    void                *tls_init_msg;             /* pointer to handshake message body */
    int                 (*tls_handshake_func)(TLS *);
    RECORD_LAYER        tls_rlayer;
    fc_u32              tls_max_send_fragment;
    fc_u32              tls_split_send_fragment;
    fc_u32              tls_max_pipelines;
    TLS_RWSTATE         tls_rwstate;
    int                 tls_hit;                    /* reusing a previous session */
    int                 tls_first_packet; 
    int                 tls_init_num; 
    int                 tls_init_off; 
    struct {
        fc_ulong        tm_message_size;
        int             tm_message_type;
    } tls_tmp;
};

struct fc_tls_ctx_t {
    const TLS_METHOD    *sc_method;
    void                *sc_ca;
    CERT                *sc_cert;
    fc_u32              sc_ca_len;
    fc_u32              sc_max_send_fragment;
    fc_u32              sc_split_send_fragment;
    fc_u32              sc_max_pipelines;
}; 

struct fc_tls_method_t {
    fc_u32          md_version;
    unsigned        md_flags;
    unsigned long   md_mask;
    int             (*md_tls_new)(TLS *s);
    void            (*md_tls_clear)(TLS *s);
    void            (*md_tls_free)(TLS *s);
    int             (*md_tls_accept)(TLS *s);
    int             (*md_tls_connect)(TLS *s);
    int             (*md_tls_read)(TLS *s, void *buf, int len);
    int             (*md_tls_peek)(TLS *s, void *buf, int len);
    int             (*md_tls_write)(TLS *s, const void *buf, int len);
    int             (*md_tls_shutdown)(TLS *s);
    int             (*md_tls_renegotiate)(TLS *s);
    int             (*md_tls_renegotiate_check)(TLS *s);
    int             (*md_tls_read_bytes)(TLS *s, int type, int *recvd_type,
                        unsigned char *buf, int len, int peek); 
    int             (*md_tls_write_bytes)(TLS *s, int type, const void *buf_,
                        int len);
    int             (*md_tls_dispatch_alert)(TLS *s); 
    long            (*md_tls_ctrl)(TLS *s, int cmd, long larg, void *parg);
#if 0
    long (*md_tls_ctx_ctrl) (TLS_CTX *ctx, int cmd, long larg, void *parg);
    const TLS_CIPHER *(*get_cipher_by_char) (const unsigned char *ptr);
    int (*put_cipher_by_char) (const TLS_CIPHER *cipher, unsigned char *ptr);
    int (*md_tls_pending) (const TLS *s); 
    int (*num_ciphers) (void);
    const TLS_CIPHER *(*get_cipher) (unsigned ncipher);
    long (*get_timeout) (void);    
    const struct ssl3_enc_method *ssl3_enc; /* Extra TLSv3/TLS stuff */
    int (*md_tls_version) (void);
    long (*md_tls_callback_ctrl) (TLS *s, int cb_id, void (*fp) (void));
    long (*md_tls_ctx_callback_ctrl) (TLS_CTX *s, int cb_id, void (*fp) (void));
#endif
};

# define IMPLEMENT_tls_meth_func(version, flags, mask, func_name, s_accept, \
                                 s_connect, enc_data) \
const TLS_METHOD *func_name(void)  \
        { \
        static const TLS_METHOD func_name##_data= { \
                .md_version = version, \
                .md_flags = flags, \
                .md_mask = mask,  \
                .md_tls_new = tls1_2_new, \
                .md_tls_clear = tls1_2_clear, \
                .md_tls_free = tls1_2_free, \
                .md_tls_accept = s_accept, \
                .md_tls_connect = s_connect, \
                .md_tls_read = tls1_2_read, \
                .md_tls_peek = tls1_2_peek, \
                .md_tls_write = tls1_2_write, \
                .md_tls_shutdown = tls1_2_shutdown, \
                .md_tls_renegotiate = tls1_2_renegotiate, \
                .md_tls_renegotiate_check = tls1_2_renegotiate_check, \
                .md_tls_read_bytes = tls1_2_read_bytes, \
                .md_tls_write_bytes = tls1_2_write_bytes, \
                .md_tls_dispatch_alert = tls1_2_dispatch_alert, \
                .md_tls_ctrl = tls1_2_ctrl, \
        }; \
        return &func_name##_data; \
        }


int tls1_2_new(TLS *s);
void tls1_2_clear(TLS *s);
void tls1_2_free(TLS *s);
int tls1_2_accept(TLS *s);
int tls1_2_connect(TLS *s);
int tls1_2_read(TLS *s, void *buf, int len);
int tls1_2_peek(TLS *s, void *buf, int len);
int tls1_2_write(TLS *s, const void *buf, int len);
int tls1_2_shutdown(TLS *s);
int tls1_2_renegotiate(TLS *s);
int tls1_2_renegotiate_check(TLS *s);
int tls1_2_dispatch_alert(TLS *s);
long tls1_2_ctrl(TLS *s, int cmd, long larg, void *parg);
int tls_security_cert(TLS *s, TLS_CTX *ctx, FC_X509 *x, int vfy, int is_ee);
TLS_RWSTATE TLS_want(const TLS *s);



#endif
