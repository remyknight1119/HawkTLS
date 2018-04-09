#ifndef __FC_TLS1_H__
#define __FC_TLS1_H__


#define TLS1_RT_HEADER_LENGTH                   5

/*
 * This is the maximum MAC (digest) size used by the SSL library. Currently
 * maximum of 20 is used by SHA1, but we reserve for future extension for
 * 512-bit hashes.
 */
#define TLS1_RT_MAX_MD_SIZE                     64

/* Maximum plaintext length: defined by SSL/TLS standards */
#define TLS1_RT_MAX_PLAIN_LENGTH                16384

/*
 * The standards give a maximum encryption overhead of 1024 bytes. In
 * practice the value is lower than this. The overhead is the maximum number
 * of padding bytes (256) plus the mac size.
 */
#define TLS1_RT_MAX_ENCRYPTED_OVERHEAD  (256 + TLS1_RT_MAX_MD_SIZE)


#define TLS1_RT_MAX_ENCRYPTED_LENGTH    \
                (TLS1_RT_MAX_ENCRYPTED_OVERHEAD+TLS1_RT_MAX_PLAIN_LENGTH)
#define TLS1_RT_MAX_PACKET_SIZE         \
                (TLS1_RT_MAX_ENCRYPTED_LENGTH+TLS1_RT_HEADER_LENGTH)

#define TLS1_MD_CLIENT_FINISHED_CONST   "\x43\x4C\x4E\x54"
#define TLS1_MD_SERVER_FINISHED_CONST   "\x53\x52\x56\x52"

#define TLS_VERSION                     0x0300
#define TLS_VERSION_MAJOR               0x03
#define TLS_VERSION_MINOR               0x00

/* CCM ciphersuites from RFC7251 */
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM            0x0300C0AC
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM            0x0300C0AD
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8          0x0300C0AE
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8          0x0300C0AF

/* ECDH GCM based ciphersuites from RFC5289 */
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256     0x0300C02B
#define TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384     0x0300C02C
#define TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256       0x0300C02F
#define TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384       0x0300C030

/* TLS v1.2 GCM ciphersuites from RFC5288 */
#define TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256         0x0300009E
#define TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384         0x0300009F

/* CCM ciphersuites from RFC6655 */
#define TLS1_CK_DHE_RSA_WITH_AES_128_CCM                0x0300C09E
#define TLS1_CK_DHE_RSA_WITH_AES_256_CCM                0x0300C09F
#define TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8              0x0300C0A2
#define TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8              0x0300C0A3

/* draft-ietf-tls-chacha20-poly1305-03 */
#define TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305         0x0300CCA8
#define TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305       0x0300CCA9
#define TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305           0x0300CCAA

/* TLS v1.2 GCM ciphersuites from RFC5288 */
#define TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256            "AES128-GCM-SHA256"
#define TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384            "AES256-GCM-SHA384"
#define TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256        "DHE-RSA-AES128-GCM-SHA256"
#define TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384        "DHE-RSA-AES256-GCM-SHA384"

/* CCM ciphersuites from RFC6655 */
#define TLS1_TXT_RSA_WITH_AES_128_CCM                   "AES128-CCM"
#define TLS1_TXT_RSA_WITH_AES_256_CCM                   "AES256-CCM"
#define TLS1_TXT_RSA_WITH_AES_128_CCM_8                 "AES128-CCM8"
#define TLS1_TXT_RSA_WITH_AES_256_CCM_8                 "AES256-CCM8"
#define TLS1_TXT_DHE_RSA_WITH_AES_128_CCM_8             "DHE-RSA-AES128-CCM8"
#define TLS1_TXT_DHE_RSA_WITH_AES_256_CCM_8             "DHE-RSA-AES256-CCM8"
#define TLS1_TXT_DHE_PSK_WITH_AES_128_CCM               "DHE-PSK-AES128-CCM"
#define TLS1_TXT_DHE_PSK_WITH_AES_256_CCM               "DHE-PSK-AES256-CCM"
#define TLS1_TXT_DHE_RSA_WITH_AES_128_CCM               "DHE-RSA-AES128-CCM"
#define TLS1_TXT_DHE_RSA_WITH_AES_256_CCM               "DHE-RSA-AES256-CCM"
#define TLS1_TXT_PSK_WITH_AES_128_CCM_8                 "PSK-AES128-CCM8"
#define TLS1_TXT_PSK_WITH_AES_256_CCM_8                 "PSK-AES256-CCM8"
#define TLS1_TXT_DHE_PSK_WITH_AES_128_CCM_8             "DHE-PSK-AES128-CCM8"
#define TLS1_TXT_DHE_PSK_WITH_AES_256_CCM_8             "DHE-PSK-AES256-CCM8"

/* CCM ciphersuites from RFC7251 */

#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM       "ECDHE-ECDSA-AES128-CCM"
#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM       "ECDHE-ECDSA-AES256-CCM"
#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM_8     "ECDHE-ECDSA-AES128-CCM8"
#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM_8     "ECDHE-ECDSA-AES256-CCM8"

/* ECDH GCM based ciphersuites from RFC5289 */
#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256    "ECDHE-ECDSA-AES128-GCM-SHA256"
#define TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    "ECDHE-ECDSA-AES256-GCM-SHA384"
#define TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256      "ECDHE-RSA-AES128-GCM-SHA256"
#define TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384      "ECDHE-RSA-AES256-GCM-SHA384"

/* draft-ietf-tls-chacha20-poly1305-03 */
#define TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305         "ECDHE-RSA-CHACHA20-POLY1305"
#define TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305       "ECDHE-ECDSA-CHACHA20-POLY1305"
#define TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305           "DHE-RSA-CHACHA20-POLY1305"

#define TLS1_MT_HELLO_REQUEST                   0
#define TLS1_MT_CLIENT_HELLO                    1
#define TLS1_MT_SERVER_HELLO                    2
#define TLS1_MT_NEWSESSION_TICKET               4
#define TLS1_MT_CERTIFICATE                     11
#define TLS1_MT_SERVER_KEY_EXCHANGE             12
#define TLS1_MT_CERTIFICATE_REQUEST             13
#define TLS1_MT_SERVER_DONE                     14
#define TLS1_MT_CERTIFICATE_VERIFY              15
#define TLS1_MT_CLIENT_KEY_EXCHANGE             16
#define TLS1_MT_FINISHED                        20
#define TLS1_MT_CERTIFICATE_STATUS              22
#define TLS1_MT_NEXT_PROTO                      67

/* Dummy message type for handling CCS like a normal handshake message */
#define TLS1_MT_CHANGE_CIPHER_SPEC              0x0101
#define TLS1_MT_CCS                             1


#endif
