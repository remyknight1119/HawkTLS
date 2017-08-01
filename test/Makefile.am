bin_PROGRAMS = ssl_test pem_test
ssl_test_SOURCES = ssl_test.c
pem_test_SOURCES = pem_test.c
ssl_test_LDADD = $(srcdir)/../tls/libdove_tls.la
pem_test_LDADD = $(srcdir)/../crypto/libdove_crypto.la

AM_CPPFLAGS = -I$(srcdir)/../include -lm
AM_CFLAGS = -Wall -Werror
