lib_LTLIBRARIES = libfc_tls.la
libfc_tls_la_SOURCES = tls.c tls_cert.c
libfc_tls_la_LDFLAGS = -version-info 1
libfc_tls_la_LIBADD = $(srcdir)/../crypto/libfc_crypto.la

AM_CPPFLAGS = -I$(srcdir)/../include
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
