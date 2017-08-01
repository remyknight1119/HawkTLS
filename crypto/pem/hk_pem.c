#include <string.h>

#include "dv_crypto.h"
#include "dv_errno.h"
#include "dv_debug.h"
#include "dv_types.h"
#include "dv_assert.h"

#define DV_PEM_FORMAT_HEADER    "-----BEGIN"
#define DV_PEM_FORMAT_END       "-----"

#define dv_conv_ascii2bin(a)       (dv_data_ascii2bin[(a)&0x7f])

#define DV_B64_EOLN                0xF0
#define DV_B64_CR                  0xF1
#define DV_B64_EOF                 0xF2
#define DV_B64_WS                  0xE0
#define DV_B64_ERROR               0xFF
#define DV_B64_NOT_BASE64(a)       (((a)|0x13) == 0xF3)

static const dv_u8 dv_data_ascii2bin[128] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xE0, 0xF0, 0xFF, 0xFF, 0xF1, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xF2, 0xFF, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};


static void
dv_b64_decode_init(dv_decode_ctx_t *ctx)
{
    ctx->pd_length = 30;
    ctx->pd_num = 0;
    ctx->pd_line_num = 0;
    ctx->pd_expect_nl = 0;
}

/*-
 * -1 for error
 *  0 for last line
 *  1 for full line
 */
int 
dv_b64_decode_update(dv_decode_ctx_t *ctx, dv_u8 *out, int *outl,
                     const dv_u8 *in, int inl)
{
    int seof = -1, eof = 0, rv = -1, ret = 0, i, v, tmp, n, ln, exp_nl;
    dv_u8       *d = NULL;

    n = ctx->pd_num;
    d = ctx->pd_data;
    ln = ctx->pd_line_num;
    exp_nl = ctx->pd_expect_nl;

    /* last line of input. */
    if ((inl == 0) || ((n == 0) && (dv_conv_ascii2bin(in[0]) == DV_B64_EOF))) {
        rv = 0;
        goto end;
    }

    /* We parse the input data */
    for (i = 0; i < inl; i++) {
        /* If the current line is > 80 characters, scream a lot */
        if (ln >= 80) {
            rv = -1;
            goto end;
        }

        /* Get char and put it into the buffer */
        tmp = *(in++);
        v = dv_conv_ascii2bin(tmp);
        /* only save the good data :-) */
        if (!DV_B64_NOT_BASE64(v)) {
            dv_assert(n < (int)sizeof(ctx->pd_data));
            d[n++] = tmp;
            ln++;
        } else if (v == DV_B64_ERROR) {
            rv = -1;
            goto end;
        }

        /*
         * have we seen a '=' which is 'definitly' the last input line.  seof
         * will point to the character that holds it. and eof will hold how
         * many characters to chop off.
         */
        if (tmp == '=') {
            if (seof == -1) {
                seof = n;
            }
            eof++;
        }

        if (v == DV_B64_CR) {
            ln = 0;
            if (exp_nl) {
                continue;
            }
        }

        /* eoln */
        if (v == DV_B64_EOLN) {
            ln = 0;
            if (exp_nl) {
                exp_nl = 0;
                continue;
            }
        }
        exp_nl = 0;

        /*
         * If we are at the end of input and it looks like a line, process
         * it.
         */
        if (((i + 1) == inl) && (((n & 3) == 0) || eof)) {
            v = DV_B64_EOF;
            /*
             * In case things were given us in really small records (so two
             * '=' were given in separate updates), eof may contain the
             * incorrect number of ending bytes to skip, so let's redo the
             * count
             */
            eof = 0;
            if (d[n - 1] == '=')
                eof++;
            if (d[n - 2] == '=')
                eof++;
            /* There will never be more than two '=' */
        }

        if ((v == DV_B64_EOF && (n & 3) == 0) || (n >= 64)) {
            /*
             * This is needed to work correctly on 64 byte input lines.  We
             * process the line and then need to accept the '\n'
             */
            if ((v != DV_B64_EOF) && (n >= 64))
                exp_nl = 1;
            if (n > 0) {
                v = dv_b64_decode_block(out, d, n);
                n = 0;
                if (v < 0) {
                    rv = 0;
                    goto end;
                }
                if (eof > v) {
                    rv = -1;
                    goto end;
                }
                ret += (v - eof);
            } else {
                eof = 1;
                v = 0;
            }

            /*
             * This is the case where we have had a short but valid input
             * line
             */
            if ((v < ctx->pd_length) && eof) {
                rv = 0;
                goto end;
            }
            ctx->pd_length = v;

            if (seof >= 0) {
                rv = 0;
                goto end;
            }
            out += v;
        }
    }
    rv = 1;
 end:
    *outl = ret;
    ctx->pd_num = n;
    ctx->pd_line_num = ln;
    ctx->pd_expect_nl = exp_nl;

    return rv;
}

int 
dv_b64_decode_block(dv_u8 *t, const dv_u8 *f, int n)
{
    int             i = 0;
    int             ret = 0;
    int             a = 0;
    int             b = 0;
    int             c = 0;
    int             d = 0;
    unsigned long   l = 0;

    /* trim white space from the start of the line. */
    while ((dv_conv_ascii2bin(*f) == DV_B64_WS) && (n > 0)) {
        f++;
        n--;
    }

    /*
     * strip off stuff at the end of the line ascii2bin values DV_B64_WS,
     * DV_B64_EOLN, DV_B64_EOLN and DV_B64_EOF
     */
    while ((n > 3) && (DV_B64_NOT_BASE64(dv_conv_ascii2bin(f[n - 1])))) {
        n--;
    }

    if (n % 4 != 0) {
        return DV_ERROR;
    }

    for (i = 0; i < n; i += 4) {
        a = dv_conv_ascii2bin(*(f++));
        b = dv_conv_ascii2bin(*(f++));
        c = dv_conv_ascii2bin(*(f++));
        d = dv_conv_ascii2bin(*(f++));
        if ((a & 0x80) || (b & 0x80) || (c & 0x80) || (d & 0x80)) {
            return DV_ERROR;
        }
        l = ((((unsigned long)a) << 18L) |
             (((unsigned long)b) << 12L) |
             (((unsigned long)c) << 6L) | (((unsigned long)d)));
        *(t++) = (dv_u8)(l >> 16L) & 0xff;
        *(t++) = (dv_u8)(l >> 8L) & 0xff;
        *(t++) = (dv_u8)(l) & 0xff;
        ret += 3;
    }

    return (ret);
}

int 
dv_b64_decode_final(dv_decode_ctx_t *ctx, dv_u8 *out, int *outl)
{
    int     i = 0;

    *outl = 0;
    if (ctx->pd_num != 0) {
        i = dv_b64_decode_block(out, ctx->pd_data, ctx->pd_num);
        if (i < 0) {
            return DV_ERROR;
        }
        ctx->pd_num = 0;
        *outl = i;
        return (1);
    }
   
    return (1);
}


int
dv_b64_decode(dv_decode_ctx_t *ctx, void *out, int *outl, void *in, int inl)
{
    int     len = 0;
    int     ret = DV_ERROR;

    dv_b64_decode_init(ctx);

    ret = dv_b64_decode_update(ctx, out, outl, in, inl);
    if (ret < 0) {
        DV_DEBUG("EVP_DecodeUpdate err!\n");
        return DV_ERROR;
    }

    len = *outl;
    ret = dv_b64_decode_final(ctx, out, outl);
    if (ret < 0) {
        DV_DEBUG("EVP_DecodeUpdate err!\n");
        return DV_ERROR;
    }

    return len;
}

int
dv_pem_decode(void **out, char *buf, int len)
{
    dv_decode_ctx_t     ctx = {};
    char                *head = NULL;
    int                 outl = 0;
    int                 size = 0;
    int                 ret = 0;

    head = strstr(buf, DV_PEM_FORMAT_HEADER);
    if (head == NULL || head != buf) {
        DV_DEBUG("Format1 error!\n");
        return DV_ERROR;
    }

    head = strstr(head + strlen(DV_PEM_FORMAT_HEADER),
            DV_PEM_FORMAT_END);
    if (head == NULL || head[sizeof(DV_PEM_FORMAT_END) - 1] != '\n') {
        DV_DEBUG("Format2 error!\n");
        return DV_ERROR;
    }

    head += sizeof(DV_PEM_FORMAT_END);
    len -= sizeof(DV_PEM_FORMAT_END);
 
    size = (len*3)/4;
    *out = dv_malloc(size);
    if (*out == NULL) {
        return DV_ERROR;
    }
    ret = dv_b64_decode(&ctx, *out, &outl, head, len);
    if (ret <= 0) {
        DV_DEBUG("Pem decode err!\n");
        dv_free(*out);
        return DV_ERROR;
    }
 
    dv_assert(ret <= size);

    return ret;
}

