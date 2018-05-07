#ifndef __FC_X509_VFY_H__
#define __FC_X509_VFY_H__

#define FC_X509_V_OK                                        0
#define FC_X509_V_ERR_UNSPECIFIED                           1
#define FC_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT             2
#define FC_X509_V_ERR_UNABLE_TO_GET_CRL                     3
#define FC_X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE      4
#define FC_X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE       5
#define FC_X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY    6
#define FC_X509_V_ERR_CERT_SIGNATURE_FAILURE                7
#define FC_X509_V_ERR_CRL_SIGNATURE_FAILURE                 8
#define FC_X509_V_ERR_CERT_NOT_YET_VALID                    9
#define FC_X509_V_ERR_CERT_HAS_EXPIRED                      10
#define FC_X509_V_ERR_CRL_NOT_YET_VALID                     11
#define FC_X509_V_ERR_CRL_HAS_EXPIRED                       12
#define FC_X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD        13
#define FC_X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD         14
#define FC_X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD        15
#define FC_X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD        16
#define FC_X509_V_ERR_OUT_OF_MEM                            17
#define FC_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT           18
#define FC_X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN             19
#define FC_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY     20
#define FC_X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE       21
#define FC_X509_V_ERR_CERT_CHAIN_TOO_LONG                   22
#define FC_X509_V_ERR_CERT_REVOKED                          23
#define FC_X509_V_ERR_INVALID_CA                            24
#define FC_X509_V_ERR_PATH_LENGTH_EXCEEDED                  25
#define FC_X509_V_ERR_INVALID_PURPOSE                       26
#define FC_X509_V_ERR_CERT_UNTRUSTED                        27
#define FC_X509_V_ERR_CERT_REJECTED                         28
/* These are 'informational' when looking for issuer cert */
#define FC_X509_V_ERR_SUBJECT_ISSUER_MISMATCH               29
#define FC_X509_V_ERR_AKID_SKID_MISMATCH                    30
#define FC_X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH           31
#define FC_X509_V_ERR_KEYUSAGE_NO_CERTSIGN                  32
#define FC_X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER              33
#define FC_X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION          34
#define FC_X509_V_ERR_KEYUSAGE_NO_CRL_SIGN                  35
#define FC_X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION      36
#define FC_X509_V_ERR_INVALID_NON_CA                        37
#define FC_X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED            38
#define FC_X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE         39
#define FC_X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED        40
#define FC_X509_V_ERR_INVALID_EXTENSION                     41
#define FC_X509_V_ERR_INVALID_POLICY_EXTENSION              42
#define FC_X509_V_ERR_NO_EXPLICIT_POLICY                    43
#define FC_X509_V_ERR_DIFFERENT_CRL_SCOPE                   44
#define FC_X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE         45
#define FC_X509_V_ERR_UNNESTED_RESOURCE                     46
#define FC_X509_V_ERR_PERMITTED_VIOLATION                   47
#define FC_X509_V_ERR_EXCLUDED_VIOLATION                    48
#define FC_X509_V_ERR_SUBTREE_MINMAX                        49
/* The application is not happy */
#define FC_X509_V_ERR_APPLICATION_VERIFICATION              50
#define FC_X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE           51
#define FC_X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX         52
#define FC_X509_V_ERR_UNSUPPORTED_NAME_SYNTAX               53
#define FC_X509_V_ERR_CRL_PATH_VALIDATION_ERROR             54
/* Another issuer check debug option */
#define FC_X509_V_ERR_PATH_LOOP                             55
/* Suite B mode algorithm violation */
#define FC_X509_V_ERR_SUITE_B_INVALID_VERSION               56
#define FC_X509_V_ERR_SUITE_B_INVALID_ALGORITHM             57
#define FC_X509_V_ERR_SUITE_B_INVALID_CURVE                 58
#define FC_X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM   59
#define FC_X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED               60
#define FC_X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256  61
/* Host, email and IP check errors */
#define FC_X509_V_ERR_HOSTNAME_MISMATCH                     62
#define FC_X509_V_ERR_EMAIL_MISMATCH                        63
#define FC_X509_V_ERR_IP_ADDRESS_MISMATCH                   64
/* DANE TLSA errors */
#define FC_X509_V_ERR_DANE_NO_MATCH                         65
/* security level errors */
#define FC_X509_V_ERR_EE_KEY_TOO_SMALL                      66
#define FC_X509_V_ERR_CA_KEY_TOO_SMALL                      67
#define FC_X509_V_ERR_CA_MD_TOO_WEAK                        68
/* Caller error */
#define FC_X509_V_ERR_INVALID_CALL                          69
/* Issuer lookup error */
#define FC_X509_V_ERR_STORE_LOOKUP                          70
/* Certificate transparency */
#define FC_X509_V_ERR_NO_VALID_SCTS                         71
#define FC_X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION          72



#endif
