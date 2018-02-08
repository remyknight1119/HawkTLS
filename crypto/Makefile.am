lib_LTLIBRARIES = libfc_crypto.la
libfc_crypto_la_SOURCES = mem.c pem/pem.c bio/bio_lib.c
libfc_crypto_la_LDFLAGS = -version-info 1

AM_CPPFLAGS = -I$(srcdir)/../include
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
