lib_LTLIBRARIES = libhk_crypto.la
libhk_crypto_la_SOURCES = hk_mem.c pem/hk_pem.c x509/hk_x509.c
libhk_crypto_la_LDFLAGS = -version-info 1

AM_CPPFLAGS = -I$(srcdir)/../include
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
