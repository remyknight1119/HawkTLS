#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/evp.h>

#include "dv_crypto.h"

int
dv_test_pem_decode(EVP_ENCODE_CTX *ctx, void *out, int *outl, void *in, int inl)
{
    int     len;
    int     ret;

    EVP_DecodeInit(ctx);

    ret = EVP_DecodeUpdate(ctx, out, outl, in, inl);
    if(ret < 0)
    {
        printf("EVP_DecodeUpdate err!\n");
        return -1;
    }

    len = *outl;
    ret = EVP_DecodeFinal(ctx, out, outl);
    if(ret < 0)
    {
        printf("EVP_DecodeUpdate err!\n");
        return -1;
    }

    return len;
}

#define DV_TEST_PEM_FILE        "test/pem/ser_cacert.pem"
#define DV_PEM_FORMAT_HEADER    "-----BEGIN"
#define DV_PEM_FORMAT_END       "-----"

int main(void)
{
    EVP_ENCODE_CTX  dctx;
    dv_decode_ctx_t ctx;
    struct stat     st;
    int             outl;
    int             ret = -1;
    int             rlen;
    int             len;
    int             fd;
    unsigned char   *buf;
    unsigned char   *head;
    unsigned char   *out;
    unsigned char   *out2;

    fd = open(DV_TEST_PEM_FILE, O_RDONLY);
    if (fd < 0) {
        printf("open %s failed!\n", DV_TEST_PEM_FILE);
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        printf("fstat %s failed!\n", DV_TEST_PEM_FILE);
        close(fd);
        return -1;
    }
    printf("file size is %d\n", (int)st.st_size);
    buf = malloc(st.st_size*3);
    if (buf == NULL) {
        printf("Malloc failed!\n");
        close(fd);
        return -1;
    }
    out = &buf[st.st_size];
    out2 = &out[st.st_size];
    rlen = read(fd, buf, st.st_size);
    printf("rlen = %d\n", rlen);
    close(fd);

    head = (unsigned char *)strstr((char *)buf, DV_PEM_FORMAT_HEADER);
    if (head == NULL || head != buf) {
        printf("Format1 error!\n");
        goto out;
    }

    head = (unsigned char *)strstr((char *)head + strlen(DV_PEM_FORMAT_HEADER),
            DV_PEM_FORMAT_END);
    if (head == NULL || head[sizeof(DV_PEM_FORMAT_END) - 1] != '\n') {
        printf("Format2 error!\n");
        goto out;
    }

    head += sizeof(DV_PEM_FORMAT_END);
    rlen -= sizeof(DV_PEM_FORMAT_END);
    ret = dv_test_pem_decode(&dctx, out, &outl, head, rlen);
    if (ret < 0) {
        printf("Pem decode err!\n");
        goto out;
    }

    len = ret;
    ret = dv_b64_decode(&ctx, out2, &outl, head, rlen);
    if (ret < 0) {
        printf("Pem decode err!\n");
        goto out;
    }
 
    if (ret != len || memcmp(out, out2, len) != 0) {
        printf("Pem decode result err!\n");
        goto out;
    }
    printf("Test pem %s ok!\n", DV_TEST_PEM_FILE);
    ret = 0;
    
out:
    free(buf);
    return ret;
}
