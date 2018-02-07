#ifndef __DV_EVP_H__
#define __DV_EVP_H__

#include "dv_types.h"

typedef struct _dv_evp_cipher_t {
    char        *ec_name;
    dv_u32      ec_name_id;
    dv_u32      ec_block_size;
    dv_u32      ec_key_len;
    dv_u32      ec_iv_len;
} dv_evp_cipher_t;


#endif
