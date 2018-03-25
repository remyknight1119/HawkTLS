#ifndef __FC_TLS_LOCL_H__
#define __FC_TLS_LOCL_H__

#include <falcontls/tls.h>
#include <falcontls/types.h>
#include <falcontls/evp.h>
#include <falcontls/safestack.h>
#include <internal/buffer.h>

#include "statem.h"
#include "record_locl.h"
#include "tls1_2.h"

#define TLS_RANDOM_SIZE                     32
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

/* Bits for algorithm_mkey (key exchange algorithm) */
/* RSA key exchange */
#define TLS_kRSA                0x00000001U
/* tmp DH key no DH cert */
#define TLS_kDHE                0x00000002U
/* ephemeral ECDH */
#define TLS_kECDHE              0x00000004U

/* Bits for algorithm_auth (server authentication) */
/* RSA auth */
#define TLS_aRSA                0x00000001U
/* ECDSA auth*/
#define TLS_aECDSA              0x00000002U

/* Bits for algorithm_enc (symmetric encryption) */
#define TLS_AES128              0x00000001U
#define TLS_AES256              0x00000002U
#define TLS_AES128GCM           0x00000004U
#define TLS_AES256GCM           0x00008008U
#define TLS_AES128CCM           0x00000010U
#define TLS_AES256CCM           0x00000020U
#define TLS_AES128CCM8          0x00000040U
#define TLS_AES256CCM8          0x00000080U
#define TLS_CHACHA20POLY1305    0x00000100U

#define TLS_AESGCM              (TLS_AES128GCM | TLS_AES256GCM)
#define TLS_AESCCM              (TLS_AES128CCM | TLS_AES256CCM | TLS_AES128CCM8 | TLS_AES256CCM8)
#define TLS_AES                 (TLS_AES128|TLS_AES256|TLS_AESGCM|TLS_AESCCM)
#define TLS_CHACHA20            (TLS_CHACHA20POLY1305)

/* Bits for algorithm_mac (symmetric authentication) */
#define TLS_SHA256              0x0000001U
#define TLS_SHA384              0x0000002U
/* Not a real MAC, just an indication it is part of cipher */
#define TLS_AEAD                0x0000004U


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

#define TLS_USE_EXPLICIT_IV(s)  \
        (s->tls_method->md_enc->em_enc_flags & TLS_ENC_FLAG_EXPLICIT_IV)

#define n2s(c,s)        ((s=(((fc_u32)((c)[0]))<< 8)| \
                             (((fc_u32)((c)[1]))    )),(c)+=2)
#define s2n(s,c)        (((c)[0]=(fc_u8)(((s)>> 8)&0xff), \
                           (c)[1]=(fc_u8)(((s)    )&0xff)),(c)+=2)

#define n2l3(c,l)       ((l =(((fc_ulong)((c)[0]))<<16)| \
                              (((fc_ulong)((c)[1]))<< 8)| \
                              (((fc_ulong)((c)[2]))    )),(c)+=3)

#define l2n3(l,c)       (((c)[0]=(fc_u8)(((l)>>16)&0xff), \
                           (c)[1]=(fc_u8)(((l)>> 8)&0xff), \
                           (c)[2]=(fc_u8)(((l)    )&0xff)),(c)+=3)


typedef struct tls_cert_pkey_t {
    FC_X509                 *cp_x509;
    FC_EVP_PKEY             *cp_privatekey;
    FC_STACK_OF(FC_X509)    *cp_chain;
} CERT_PKEY;

typedef struct tls_cert_t {
    CERT_PKEY           *ct_key;
    CERT_PKEY           ct_pkeys[FC_EVP_PKEY_NUM];
} CERT;

typedef struct tls1_state_t {
    fc_u8   st_server_random[TLS_RANDOM_SIZE];
    fc_u8   st_client_random[TLS_RANDOM_SIZE];
    int     st_alert_dispatch;
} TLS1_STATE;

typedef struct tls_session_t {
    fc_u32                  se_flags;
    fc_u32                  se_session_id_length;
    fc_u8                   se_session_id[FC_TLS_MAX_SESSION_ID_LENGTH];
    FC_STACK_OF(TLS_CIPHER) *se_ciphers;
} TLS_SESSION;

struct fc_tls_t {
    TLS_STATEM                  tls_statem;
    bool                        tls_server;
    bool                        tls_shutdown;
    const TLS_METHOD            *tls_method;
    TLS_CTX                     *tls_ctx;
    CERT                        *tls_cert;
    FC_BIO                      *tls_rbio;
    FC_BIO                      *tls_wbio;
    FC_BUF_MEM                  *tls_init_buf;
    void                        *tls_init_msg;   /* pointer to handshake message body */
    TLS_SESSION                 *tls_session;
    FC_EVP_CIPHER_CTX           *tls_enc_write_ctx;
    FC_STACK_OF(TLS_CIPHER)     *tls_cipher_list;
    int                         (*tls_handshake_func)(TLS *);
    RECORD_LAYER                tls_rlayer;
    TLS1_STATE                  tls1;
    fc_u32                      tls_max_send_fragment;
    fc_u32                      tls_split_send_fragment;
    fc_u32                      tls_max_pipelines;
    TLS_RWSTATE                 tls_rwstate;
    int                         tls_version;
    int                         tls_fd;
    int                         tls_hit;                    /* reusing a previous session */
    int                         tls_first_packet; 
    int                         tls_init_num; 
    int                         tls_init_off; 
    int                         tls_new_session;
    int                         tls_renegotiate; 

    struct {
        fc_ulong                tm_message_size;
        int                     tm_message_type;
    } tls_tmp;
};

typedef struct tls_enc_method_t {
    int         (*em_enc)(TLS *, TLS_RECORD *, fc_u32, int);
    int         (*em_set_handshake_header)(TLS *s, int type, fc_ulong len);
    /* Handshake header length */
    fc_u32      em_hhlen;
    fc_u32      em_enc_flags;
} TLS_ENC_METHOD;

#define TLS_GET_HM_HEADER_LENGTH(s) s->tls_method->md_enc->em_hhlen
#define tls_handshake_start(s) \
    (((fc_u8 *)s->tls_init_buf->bm_data) + TLS_GET_HM_HEADER_LENGTH(s))
#define tls_set_handshake_header(s, htype, len) \
    s->tls_method->md_enc->em_set_handshake_header(s, htype, len)

#define TLS_ENC_FLAG_EXPLICIT_IV        0x1

struct fc_tls_ctx_t {
    const TLS_METHOD            *sc_method;
    void                        *sc_ca;
    CERT                        *sc_cert;
    FC_STACK_OF(TLS_CIPHER)     *sc_cipher_list;
    FC_STACK_OF(TLS_CIPHER)     *sc_cipher_list_by_id;
    fc_u32                      sc_ca_len;
    fc_u32                      sc_max_send_fragment;
    fc_u32                      sc_split_send_fragment;
    fc_u32                      sc_max_pipelines;
}; 

struct tls_cipher_t {
    const char      *cp_name;           /* text name */
    fc_u32          cp_id;                /* id, 4 bytes, first is version */
    fc_u32          cp_algorithm_mkey;    /* key exchange algorithm */
    fc_u32          cp_algorithm_auth;    /* server authentication */
    fc_u32          cp_algorithm_enc;     /* symmetric encryption */
    fc_u32          cp_algorithm_mac;     /* symmetric authentication */
    fc_u32          cp_alg_bits;          /* Number of bits for algorithm */
    int             cp_strength_bits;     /* Number of bits really used */
};

struct fc_tls_method_t {
    fc_u32                  md_version;
    unsigned                md_flags;
    fc_ulong                md_mask;
    int                     (*md_tls_new)(TLS *s);
    void                    (*md_tls_clear)(TLS *s);
    void                    (*md_tls_free)(TLS *s);
    int                     (*md_tls_accept)(TLS *s);
    int                     (*md_tls_connect)(TLS *s);
    int                     (*md_tls_read)(TLS *s, void *buf, int len);
    int                     (*md_tls_peek)(TLS *s, void *buf, int len);
    int                     (*md_tls_write)(TLS *s, const void *buf, int len);
    int                     (*md_tls_shutdown)(TLS *s);
    int                     (*md_tls_renegotiate)(TLS *s);
    int                     (*md_tls_renegotiate_check)(TLS *s);
    int                     (*md_tls_read_bytes)(TLS *s, int type, int *recvd_type,
                                fc_u8 *buf, int len, int peek); 
    int                     (*md_tls_write_bytes)(TLS *s, int type, 
                                const void *buf_, int len);
    int                     (*md_tls_dispatch_alert)(TLS *s); 
    long                    (*md_tls_ctrl)(TLS *s, int cmd, long larg,
                                void *parg);
    long                    (*md_tls_ctx_ctrl)(TLS_CTX *ctx, int cmd,
                                long larg, void *parg);
    const TLS_CIPHER        *(*md_get_cipher_by_char)(const fc_u8 *ptr);
    int                     (*md_put_cipher_by_char)(const TLS_CIPHER *cipher,
                                fc_u8 *ptr);
    int                     (*md_tls_pending) (const TLS *s); 
    int                     (*md_num_ciphers) (void);
    const TLS_CIPHER        *(*md_get_cipher) (unsigned ncipher);
    long                    (*md_get_timeout)(void);
    const TLS_ENC_METHOD    *md_enc; /* Extra TLS stuff */
    int                     (*md_tls_version) (void);
};

extern TLS_ENC_METHOD const TLSv1_2_enc_data;

#define IMPLEMENT_tls_meth_func(version, flags, mask, func_name, s_accept, \
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
                .md_num_ciphers = tls1_2_num_ciphers, \
                .md_get_cipher = tls1_2_get_cipher, \
                .md_get_cipher_by_char = tls1_2_get_cipher_by_char, \
                .md_put_cipher_by_char = tls1_2_put_cipher_by_char, \
                .md_enc = enc_data, \
        }; \
        return &func_name##_data; \
        }


int tls_security_cert(TLS *s, TLS_CTX *ctx, FC_X509 *x, int vfy, int is_ee);
int tls_fill_hello_random(TLS *s, int server, fc_u8 *result, int len);
int tls1_enc(TLS *s, TLS_RECORD *recs, fc_u32 n_recs, int sending);
int tls1_set_handshake_header(TLS *s, int htype, fc_ulong len);
TLS_RWSTATE TLS_want(const TLS *s);
CERT *tls_cert_new(void);
CERT *tls_cert_dup(CERT *cert);
void tls_cert_free(CERT *c);
int tls_get_new_session(TLS *s, int session);
TLS_SESSION *TLS_SESSION_new(void);
void TLS_SESSION_free(TLS_SESSION *ss);
FC_STACK_OF(TLS_CIPHER) *tls_create_cipher_list(const TLS_METHOD *meth,
                                                FC_STACK_OF(TLS_CIPHER) **pref,
                                                FC_STACK_OF(TLS_CIPHER)
                                                    **sorted,
                                                const char *rule_str,
                                                CERT *c);
int tls_cipher_disabled(TLS *s, const TLS_CIPHER *c, int op, int ecdhe);
int tls_cipher_ptr_id_cmp(const TLS_CIPHER *const *ap, const TLS_CIPHER *
                            const *bp);


#endif
