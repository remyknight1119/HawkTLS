lib_LTLIBRARIES = libfc_crypto.la
libfc_crypto_la_SOURCES = mem.c pem/pem.c bio/bio_lib.c bio/bio_file.c \
						  evp/p_lib.c buffer/buffer.c x509/x509.c \
						  pem/pem_lib.c bio/bio_socket.c stack/stack.c \
						  evp/evp_lib.c x509/x_x509.c asn1/tasn_new.c \
						  asn1/tasn_fre.c asn1/tasn_enc.c asn1/tasn_dec.c \
						  x509/x509_cmp.c
libfc_crypto_la_LDFLAGS = -version-info 1

AM_CPPFLAGS = -I$(srcdir)/../include
AM_CFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = foreign subdir-objects
