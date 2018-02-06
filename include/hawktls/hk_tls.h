#ifndef __HK_TLS_H__
#define __HK_TLS_H__

#include "hawktls/hk_types.h"
#include "hawktls/hk_x509.h"

#define HK_TLS1_0_VERSION                   0x0301
#define HK_TLS1_2_VERSION                   0x0303
#define HK_TLS1_3_VERSION                   0x0304
#define HK_TLS_MAX_VERSION                  HK_TLS1_3_VERSION

#define HK_TLS_MSG_MAX_LEN                  1500

#define HK_TLS_RANDOM_BYTES_LEN             28

#define HK_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384        (0xc030)
#define HK_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256        (0xc02f)
#define HK_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384      (0xc02c)
#define HK_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256      (0xc02b)

#define HK_TLS_RSA_WITH_AES_256_GCM_SHA384              (0x009d)
#define HK_TLS_RSA_WITH_AES_256_CBC_SHA256              (0x003d)
#define HK_TLS_RSA_WITH_AES_128_GCM_SHA256              (0x009c)
#define HK_TLS_RSA_WITH_AES_128_CBC_SHA256              (0x003c)

#define HK_TLS_VERIFY_NONE                      0x00
#define HK_TLS_VERIFY_PEER                      0x01
#define HK_TLS_VERIFY_FAIL_IF_NO_PEER_CERT      0x02
#define HK_TLS_VERIFY_CLIENT_ONCE               0x04

enum {
    HK_TLS_STATE_INIT,
    HK_TLS_STATE_HELLO,
    HK_TLS_STATE_KEY_EXCHANGE,
};

struct _hk_tls_method_t;
struct _hk_tls_ctx_t;

typedef struct _hk_tls_t {
    hk_u32                          tls_state;
    const struct _hk_tls_method_t   *tls_method;
    struct _hk_tls_ctx_t            *tls_ctx;
    void                            *tls_ca;
    bool                            tls_server;
    int                             tls_fd;
    hk_u32                          tls_ca_len;
    hk_u32                          tls_ca_mode;
    int                             (*tls_ca_callback)(int ok, hk_x509_t *x509);
    /* 
     * pointer to handshake message body, set by
     * md_tls_get_message 
     */
    void                            *tls_msg;
    int                             tls_mlen;
    hk_u16                          tls_cipher_suite;
} TLS;

typedef struct _hk_tls_method_t {
    hk_u16      md_version;
    hk_u16      md_msg_max_len;
    int         (*md_tls_new)(TLS *s);
    void        (*md_tls_free)(TLS *s);
    int         (*md_tls_accept)(TLS *s);
    int         (*md_tls_connect)(TLS *s);
    int         (*md_tls_read)(TLS *s, void *buf, hk_u32 len);
//    int         (*md_tls_peek)(TLS *s, void *buf, hk_u32 len);
    int         (*md_tls_write)(TLS *s, const void *buf, hk_u32 len);
    int         (*md_tls_shutdown)(TLS *s);
    int         (*md_tls_hello)(TLS *s);
    int         (*md_tls_get_message)(TLS *s);
    int         (*md_tls_parse_message)(TLS *s);
    int         (*md_bio_get_time)(hk_u32 *t);
    int         (*md_bio_read)(int fd, void *buf, hk_u32 len);
    int         (*md_bio_read_file)(const char *file, void **data);
    int         (*md_bio_write)(int fd, const void *buf, hk_u32 len);
} TLS_METHOD;

typedef struct _hk_tls_ctx_t {
    const TLS_METHOD        *sc_method;
    void                    *sc_ca;
    hk_u32                  sc_ca_len;
} TLS_CTX; 

typedef enum _HK_TLS_CONTENT_TYPE_E {
    HK_TLS_CHANGE_CIPHER_SPEC = 20,
    HK_TLS_CONTENT_TYPE_ALERT = 21,
    HK_TLS_CONTENT_TYPE_HANDSHAKE = 22,
    HK_TLS_CONTENT_TYPE_APPLICATION_DATA = 23,
    HK_TLS_CONTENT_TYPE_MAX = 255,
} HK_TLS_CONTENT_TYPE_E;

typedef enum _HK_TLS_HANDSHAKE_TYPE_E {
    HK_TLS_HANDSHAKE_TYPE_HELLO_REQUEST = 0,
    HK_TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 1,
    HK_TLS_HANDSHAKE_TYPE_SERVER_HELLO = 2,
    HK_TLS_HANDSHAKE_TYPE_SESSION_TICKET = 4,
    HK_TLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST = 6,
    HK_TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8,
    HK_TLS_HANDSHAKE_TYPE_CERTIFICATE = 11,
    HK_TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12,
    HK_TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13,
    HK_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14,
    HK_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15,
    HK_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16,
    HK_TLS_HANDSHAKE_TYPE_SERVER_CONFIGURATION = 17,
    HK_TLS_HANDSHAKE_TYPE_FINISHED = 20,
    HK_TLS_HANDSHAKE_TYPE_KEY_UPDATE = 24,
    HK_TLS_HANDSHAKE_TYPE_MAX = 255,
} HK_TLS_HANDSHAKE_TYPE_E; 

#pragma pack (1)

typedef struct _hk_proto_version_t {
    union {
        hk_u16  pv_version;
        struct {
            hk_u8   pv_major;
            hk_u8   pv_minor;
        };
    };
} hk_proto_version_t;

typedef struct _hk_tls_record_header_t {
    hk_u8                   rh_content_type;
    hk_proto_version_t      rh_version;
    hk_u16                  rh_length;
} hk_tls_record_header_t;

typedef struct _hk_tls_handshake_header_t {
    hk_u8                   hh_msg_type;
    hk_u8                   hh_length[3];
} hk_tls_handshake_header_t;

extern TLS_CTX *hk_tls_ctx_new(const TLS_METHOD *meth);
extern void hk_tls_ctx_free(TLS_CTX *ctx);

extern TLS *hk_tls_new(TLS_CTX *ctx);
extern void hk_tls_free(TLS *s);

extern int hk_library_init(void);
extern void hk_add_all_algorighms(void);
extern void hk_load_error_strings(void);

extern int hk_tls_accept(TLS *s);
extern int hk_tls_connect(TLS *s);
extern int hk_tls_set_fd(TLS *s, int fd);
extern void hk_tls_set_verify(TLS *s, hk_u32 mode,
            int (*callback)(int ok, hk_x509_t *x509));
extern int hk_tls_read(TLS *s, void *buf, hk_u32 len);
extern int hk_tls_write(TLS *s, const void *buf, hk_u32 len);
extern int hk_tls_shutdown(TLS *s);
extern int hk_tls_get_message(TLS *s);

extern int hk_undefined_function(TLS *s);

extern int hk_tls_ctx_use_certificate_file(TLS_CTX *ctx,
            const char *file, hk_u32 type);
extern int hk_tls_ctx_use_private_key_file(TLS_CTX *ctx,
            const char *file, hk_u32 type);
extern int hk_tls_ctx_check_private_key(const TLS_CTX *ctx);


extern void hk_tls_free(TLS *s);
extern int hk_tls_bio_accept(TLS *s);
extern int hk_tls_bio_connect(TLS *s);
extern int hk_tls_bio_read(TLS *s, void *buf, hk_u32 len);
extern int hk_tls_bio_write(TLS *s, const void *buf, hk_u32 len);
extern int hk_tls_bio_shutdown(TLS *s);
extern int hk_tls_bio_get_message(TLS *s);

extern const TLS_METHOD *hk_tls_client_method(void);
extern const TLS_METHOD *hk_tls_server_method(void);

#endif
