
#include <falcontls/types.h>
#include <falcontls/evp.h>

#include <openssl/evp.h>

const FC_EVP_CIPHER *
FC_EVP_CIPHER_CTX_cipher(const FC_EVP_CIPHER_CTX *ctx)
{
    const EVP_CIPHER_CTX    *c = (const EVP_CIPHER_CTX *)ctx;

    return (const FC_EVP_CIPHER *)EVP_CIPHER_CTX_cipher(c);
}

fc_ulong
FC_EVP_CIPHER_flags(const FC_EVP_CIPHER *cipher)
{
    return EVP_CIPHER_flags((const EVP_CIPHER *)cipher);
}

const FC_EVP_MD *
FC_EVP_MD_CTX_md(const FC_EVP_MD_CTX *ctx)
{
    return (const FC_EVP_MD *)EVP_MD_CTX_md((const EVP_MD_CTX *)ctx);
}

int
FC_EVP_MD_size(const FC_EVP_MD *md)
{
    return EVP_MD_size((const EVP_MD *)md);
}
