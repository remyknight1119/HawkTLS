#include <falcontls/types.h>
#include <falcontls/x509.h>
#include <fc_log.h>

#include "internal/x509.h"

#include <openssl/x509.h>

int
FC_X509_up_ref(FC_X509 *x)
{
    //return X509_up_ref((X509 *)x);
    return 1;
}
