#ifndef __FC_TLS_ALERT_H__
#define __FC_TLS_ALERT_H__

#define TLS_AL_WARNING                  1
#define TLS_AL_FATAL                    2

#define TLS_AD_CLOSE_NOTIFY                     0
#define TLS_AD_UNEXPECTED_MESSAGE               10/* fatal */
#define TLS_AD_BAD_RECORD_MAC                   20/* fatal */
#define TLS_AD_DECRYPTION_FAILED                21
#define TLS_AD_RECORD_OVERFLOW                  22
#define TLS_AD_DECOMPRESSION_FAILURE            30/* fatal */
#define TLS_AD_HANDSHAKE_FAILURE                40/* fatal */
#define TLS_AD_NO_CERTIFICATE                   41
#define TLS_AD_BAD_CERTIFICATE                  42
#define TLS_AD_UNSUPPORTED_CERTIFICATE          43
#define TLS_AD_CERTIFICATE_REVOKED              44
#define TLS_AD_CERTIFICATE_EXPIRED              45
#define TLS_AD_CERTIFICATE_UNKNOWN              46
#define TLS_AD_ILLEGAL_PARAMETER                47/* fatal */
#define TLS_AD_UNKNOWN_CA                       48/* fatal */
#define TLS_AD_ACCESS_DENIED                    49/* fatal */
#define TLS_AD_DECODE_ERROR                     50/* fatal */
#define TLS_AD_DECRYPT_ERROR                    51
#define TLS_AD_EXPORT_RESTRICTION               60/* fatal */
#define TLS_AD_PROTOCOL_VERSION                 70/* fatal */
#define TLS_AD_INSUFFICIENT_SECURITY            71/* fatal */
#define TLS_AD_INTERNAL_ERROR                   80/* fatal */
#define TLS_AD_INAPPROPRIATE_FALLBACK           86/* fatal */
#define TLS_AD_USER_CANCELLED                   90
#define TLS_AD_NO_RENEGOTIATION                 100
/* codes 110-114 are from RFC3546 */
#define TLS_AD_UNSUPPORTED_EXTENSION            110
#define TLS_AD_CERTIFICATE_UNOBTAINABLE         111
#define TLS_AD_UNRECOGNIZED_NAME                112
#define TLS_AD_BAD_CERTIFICATE_STATUS_RESPONSE  113
#define TLS_AD_BAD_CERTIFICATE_HASH_VALUE       114
#define TLS_AD_UNKNOWN_PSK_IDENTITY             115/* fatal */
#define TLS_AD_NO_APPLICATION_PROTOCOL          120 /* fatal */



int tls_send_alert(TLS *s, int level, int desc);

#endif
