bin_PROGRAMS = ssl_test pem_test bn_test
ssl_test_SOURCES = s_test.c
pem_test_SOURCES = pem_test.c
bn_test_SOURCES = bn_test.c
ssl_test_LDADD = $(srcdir)/../tls/libhk_tls.la
pem_test_LDADD = $(srcdir)/../crypto/libhk_crypto.la

AM_CPPFLAGS = -I$(srcdir)/../include -lm
AM_CFLAGS = -Wall -Werror
