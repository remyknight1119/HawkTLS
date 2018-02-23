bin_PROGRAMS = tls_test #pem_test bn_test rsa_test
tls_test_SOURCES = tls_test.c tls_lib.c
tls_test_LDADD = $(srcdir)/../tls/libfc_tls.la $(srcdir)/../crypto/libfc_crypto.la
#pem_test_SOURCES = pem_test.c hk_test.c
#pem_test_LDADD = $(srcdir)/../crypto/libhk_crypto.la
#bn_test_SOURCES = bn_test.c hk_test.c
#bn_test_LDADD = $(srcdir)/../crypto/libhk_crypto.la
#rsa_test_SOURCES = rsa_test.c
#rsa_test_LDADD = $(srcdir)/../crypto/libhk_crypto.la

AM_CPPFLAGS = -I$(srcdir)/../include -lm
AM_CFLAGS = -Wall -Werror
