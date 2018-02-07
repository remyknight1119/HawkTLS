
#include <falcontls/tls.h>
#include "statem.h"
#include "tls_locl.h"

IMPLEMENT_tls_meth_func(FC_TLS1_2_VERSION, 0, 0,
         FCTLS_method,                    
         fctls_statem_accept,            
         fctls_statem_connect, NULL)

