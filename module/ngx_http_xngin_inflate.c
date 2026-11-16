#include "ngx_http_xngin_module.h"

#include <zlib.h>
#include <brotli/decode.h>


/*
 * Held-response decompression for the agent view.  The upstream wire
 * bytes stay compressed for the client; the agent's BODY frames carry
 * the inflated plaintext when Content-Encoding is gzip/deflate/br.
 *
 * Also home to the streamed-replacement BODY frame collector: a verdict
 * carrying "body-stream" keeps the decision stream open so the agent can
 * stream a replacement body back on the same sid, terminated by
 * FL_BODY_LAST.
 */


/* inflate an entire buffered chain into one pool buffer.
   enc: XNAP_DEC_GZIP (gzip + deflate via zlib autodetect) or
   XNAP_DEC_BR.  out->len > cap fails with NGX_BUSY. */
ngx_int_t
ngx_http_xngin_inflate(ngx_http_request_t *r, ngx_chain_t *in,
    ngx_str_t *out, unsigned enc, size_t cap)
{
    ngx_chain_t *cl;

    out->len = 0;
    out->data = ngx_pnalloc(r->pool, cap ? cap : 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    if (enc == XNAP_DEC_BR) {
        BrotliDecoderState *st;
        BrotliDecoderResult res = BROTLI_DECODER_RESULT_SUCCESS;
        const uint8_t      *next_in = NULL;
        uint8_t            *next_out = out->data;
        size_t              avail_in = 0, avail_out = cap;

        st = BrotliDecoderCreateInstance(NULL, NULL, NULL);
        if (st == NULL) {
            return NGX_ERROR;
        }

        for (cl = in; cl; cl = cl->next) {
            if (cl->buf == NULL) {
                continue;
            }
            next_in = (const uint8_t *) cl->buf->pos;
            avail_in = cl->buf->last - cl->buf->pos;
            if (avail_in == 0) {
                continue;
            }
            res = BrotliDecoderDecompressStream(st, &avail_in, &next_in,
                                                &avail_out, &next_out, NULL);
            if (res == BROTLI_DECODER_RESULT_ERROR) {
                BrotliDecoderDestroyInstance(st);
                return NGX_ERROR;
            }
            if (res == BROTLI_DECODER_RESULT_SUCCESS) {
                break;
            }
        }

        if (res == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
            /* truncated compressed body */
            BrotliDecoderDestroyInstance(st);
            return NGX_ERROR;
        }
        if (res == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            BrotliDecoderDestroyInstance(st);
            return NGX_BUSY;
        }

        BrotliDecoderDestroyInstance(st);
        out->len = next_out - out->data;
        return NGX_OK;
    }

    /* gzip / deflate: windowBits 15+32 autodetects zlib and gzip */
    {
        z_stream  z;
        int       zrc = Z_OK;

        ngx_memzero(&z, sizeof(z));
        if (inflateInit2(&z, 15 + 32) != Z_OK) {
            return NGX_ERROR;
        }

        z.next_out = out->data;
        z.avail_out = (uInt) cap;

        for (cl = in; cl; cl = cl->next) {
            if (cl->buf == NULL) {
                continue;
            }
            z.next_in = cl->buf->pos;
            z.avail_in = (uInt) (cl->buf->last - cl->buf->pos);

            while (z.avail_in > 0) {
                zrc = inflate(&z, Z_NO_FLUSH);
                if (zrc == Z_STREAM_END) {
                    goto done;
                }
                if (zrc != Z_OK) {
                    inflateEnd(&z);
                    return NGX_ERROR;
                }
                if (z.avail_out == 0 && z.avail_in > 0) {
                    inflateEnd(&z);
                    return NGX_BUSY;
                }
            }
        }

        /* input consumed without STREAM_END */
        zrc = inflate(&z, Z_FINISH);
        if (zrc != Z_STREAM_END) {
            inflateEnd(&z);
            return (z.avail_out == 0) ? NGX_BUSY : NGX_ERROR;
        }

done:
        out->len = z.total_out;
        inflateEnd(&z);
    }

    return NGX_OK;
}


/* append an agent-pushed BODY frame to the replacement accumulator;
   on FL_BODY_LAST hand off to the direction-specific finalizer */
ngx_int_t
ngx_http_xngin_repl_body(ngx_http_xngin_conn_t *c,
    ngx_http_xngin_ctx_t *ctx, uint32_t flags,
    u_char *payload, size_t len)
{
    ngx_http_request_t        *r = ctx->r;
    ngx_http_xngin_loc_conf_t *lcf;
    ngx_chain_t               *nl;
    ngx_buf_t                 *nb;
    u_char                    *data;
    size_t                     cap;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xngin_module);
    cap = ctx->is_resp ? lcf->res_body_max : lcf->body_max;

    if (ctx->repl_len + len > cap) {
        /* oversized replacement: drop the stream, fail policy decides */
        ngx_http_xngin_stream_del(c, ctx->stream_id);
        ctx->conn = NULL;
        ctx->repl_wait = 0;
        ngx_str_set(&ctx->error, "repl-too-big");
        if (ctx->is_resp) {
            ngx_http_xngin_resp_fail(ctx, "repl");
        } else {
            ngx_http_xngin_fail(ctx, "repl");
        }
        return NGX_OK;
    }

    if (len) {
        nb = ngx_calloc_buf(r->pool);
        nl = ngx_alloc_chain_link(r->pool);
        data = ngx_pnalloc(r->pool, len);
        if (nb == NULL || nl == NULL || data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(data, payload, len);
        nb->pos = data;
        nb->last = data + len;
        nb->memory = 1;
        nl->buf = nb;
        nl->next = NULL;
        if (ctx->repl_tail == NULL) {
            ctx->repl_tail = &ctx->repl;
        }
        *ctx->repl_tail = nl;
        ctx->repl_tail = &nl->next;
        ctx->repl_len += len;
    }

    if (!(flags & XNAP_FL_BODY_LAST)) {
        return NGX_OK;
    }

    ctx->repl_wait = 0;
    ngx_http_xngin_stream_del(c, ctx->stream_id);
    ctx->conn = NULL;
    ctx->state = XNAP_ST_DONE;

    if (ctx->timer && ctx->timer->timer_set) {
        ngx_del_timer(ctx->timer);
    }

    if (ctx->is_resp) {
        ngx_http_xngin_resp_repl_done(ctx);
    } else {
        ngx_http_xngin_req_repl_done(ctx);
    }

    return NGX_OK;
}
