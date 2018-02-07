#ifndef __FC_STATEM_H__
#define __FC_STATEM_H__

#include <falcontls/tls.h>

int fctls_statem_accept(TLS *s);
int fctls_statem_connect(TLS *s);

#endif
