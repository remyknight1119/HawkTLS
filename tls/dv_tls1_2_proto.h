#ifndef __DV_TLS1_2_PROTO_H__
#define __DV_TLS2_2_PROTO_H__

#include "dv_ssl.h"
#include "dv_tls.h"

typedef struct _dv_tlsv1_2_random_t {
    dv_u32      rd_gmt_unix_time;
    dv_u8       rd_random_bytes[DV_TLS_RANDOM_BYTES_LEN];
} dv_tlsv1_2_random_t;

typedef struct _dv_tlsv1_2_client_hello_t {
    dv_proto_version_t          ch_version;
    dv_tlsv1_2_random_t         ch_random;
    dv_u8                       ch_session_id;
} dv_tlsv1_2_client_hello_t;

typedef struct _dv_tlsv1_2_server_hello_t {
    dv_proto_version_t          sh_version;
    dv_tlsv1_2_random_t         sh_random;
    dv_u8                       sh_session_id;
    dv_u16                      sh_cipher_suite;
    dv_u8                       sh_compress_method;
    dv_u16                      sh_ext_len;
} dv_tlsv1_2_server_hello_t;


extern int dv_tls1_2_client_hello(dv_ssl_t *s);
extern int dv_tls1_2_server_hello(dv_ssl_t *s);
extern int dv_tls1_2_parse_message(dv_ssl_t *s);


#endif
