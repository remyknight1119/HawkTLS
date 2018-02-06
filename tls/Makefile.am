lib_LTLIBRARIES = libhk_tls.la
libhk_tls_la_SOURCES = hk_tls.c hk_tls_cert.c
libhk_tls_la_LDFLAGS = -version-info 1
libhk_tls_la_LIBADD = $(srcdir)/../crypto/libhk_crypto.la

AM_CPPFLAGS = -I$(srcdir)/../include
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
