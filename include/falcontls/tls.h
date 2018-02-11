#ifndef __FC_TLS_H__
#define __FC_TLS_H__

#include "falcontls/types.h"
#include "falcontls/x509.h"

#define FC_TLS1_0_VERSION                   0x0301
#define FC_TLS1_2_VERSION                   0x0303
#define FC_TLS1_3_VERSION                   0x0304
#define FC_TLS_MAX_VERSION                  FC_TLS1_3_VERSION

#define FC_TLS_MSG_MAX_LEN                  1500

#define FC_TLS_RANDOM_BYTES_LEN             28

#define FC_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384        (0xc030)
#define FC_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256        (0xc02f)
#define FC_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384      (0xc02c)
#define FC_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256      (0xc02b)

#define FC_TLS_RSA_WITH_AES_256_GCM_SHA384              (0x009d)
#define FC_TLS_RSA_WITH_AES_256_CBC_SHA256              (0x003d)
#define FC_TLS_RSA_WITH_AES_128_GCM_SHA256              (0x009c)
#define FC_TLS_RSA_WITH_AES_128_CBC_SHA256              (0x003c)

#define FC_TLS_VERIFY_NONE                      0x00
#define FC_TLS_VERIFY_PEER                      0x01
#define FC_TLS_VERIFY_FAIL_IF_NO_PEER_CERT      0x02
#define FC_TLS_VERIFY_CLIENT_ONCE               0x04

#define FC_TLS_RT_MAX_PLAIN_LENGTH              16384

enum {
    FC_TLS_STATE_INIT,
    FC_TLS_STATE_HELLO,
    FC_TLS_STATE_KEY_EXCHANGE,
};

typedef enum _FC_TLS_CONTENT_TYPE_E {
    FC_TLS_CHANGE_CIPHER_SPEC = 20,
    FC_TLS_CONTENT_TYPE_ALERT = 21,
    FC_TLS_CONTENT_TYPE_HANDSHAKE = 22,
    FC_TLS_CONTENT_TYPE_APPLICATION_DATA = 23,
    FC_TLS_CONTENT_TYPE_MAX = 255,
} FC_TLS_CONTENT_TYPE_E;

typedef enum _FC_TLS_HANDSHAKE_TYPE_E {
    FC_TLS_HANDSHAKE_TYPE_HELLO_REQUEST = 0,
    FC_TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 1,
    FC_TLS_HANDSHAKE_TYPE_SERVER_HELLO = 2,
    FC_TLS_HANDSHAKE_TYPE_SESSION_TICKET = 4,
    FC_TLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST = 6,
    FC_TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8,
    FC_TLS_HANDSHAKE_TYPE_CERTIFICATE = 11,
    FC_TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12,
    FC_TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13,
    FC_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14,
    FC_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15,
    FC_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16,
    FC_TLS_HANDSHAKE_TYPE_SERVER_CONFIGURATION = 17,
    FC_TLS_HANDSHAKE_TYPE_FINISHED = 20,
    FC_TLS_HANDSHAKE_TYPE_KEY_UPDATE = 24,
    FC_TLS_HANDSHAKE_TYPE_MAX = 255,
} FC_TLS_HANDSHAKE_TYPE_E; 

#pragma pack (1)

typedef struct _fc_proto_version_t {
    union {
        fc_u16  pv_version;
        struct {
            fc_u8   pv_major;
            fc_u8   pv_minor;
        };
    };
} fc_proto_version_t;

typedef struct _fc_tls_record_header_t {
    fc_u8                   rh_content_type;
    fc_proto_version_t      rh_version;
    fc_u16                  rh_length;
} fc_tls_record_header_t;

typedef struct _fc_tls_handshake_header_t {
    fc_u8                   hh_msg_type;
    fc_u8                   hh_length[3];
} fc_tls_handshake_header_t;

extern TLS_CTX *FCTLS_ctx_new(const TLS_METHOD *meth);
extern void FCTLS_ctx_free(TLS_CTX *ctx);

extern TLS *FCTLS_new(TLS_CTX *ctx);
extern void FCTLS_free(TLS *s);

extern int FALCONTLS_init(void);
extern void FalconTLS_add_all_algorighms(void);

extern int FCTLS_accept(TLS *s);
extern int FCTLS_connect(TLS *s);
extern int FCTLS_set_fd(TLS *s, int fd);
extern void FCTLS_set_verify(TLS *s, fc_u32 mode,
            int (*callback)(int ok, FC_X509 *x509));
extern int FCTLS_read(TLS *s, void *buf, fc_u32 len);
extern int FCTLS_write(TLS *s, const void *buf, fc_u32 len);
extern int FCTLS_shutdown(TLS *s);
extern int FCTLS_get_message(TLS *s);

extern int fc_undefined_function(TLS *s);

extern int FCTLS_ctx_use_certificate_file(TLS_CTX *ctx,
            const char *file, fc_u32 type);
extern int FCTLS_ctx_use_private_key_file(TLS_CTX *ctx,
            const char *file, fc_u32 type);
extern int FCTLS_ctx_check_private_key(const TLS_CTX *ctx);


extern void FCTLS_free(TLS *s);
extern int FCTLS_bio_accept(TLS *s);
extern int FCTLS_bio_connect(TLS *s);
extern int FCTLS_bio_read(TLS *s, void *buf, fc_u32 len);
extern int FCTLS_bio_write(TLS *s, const void *buf, fc_u32 len);
extern int FCTLS_bio_shutdown(TLS *s);
extern int FCTLS_bio_get_message(TLS *s);

extern const TLS_METHOD *FCTLS_method(void);

#endif
