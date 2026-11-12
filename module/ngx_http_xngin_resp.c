#include "ngx_http_xngin_module.h"


/*
 * Response side: verdict-time response mutations (res-hdr-set/unset,
 * res-body) applied in the output filter chain, plus the optional
 * http-response agent round-trip (xngin_response) that holds the
 * response while the agent inspects it.
 *
 * Holding: as top header filter we may return NGX_OK without calling
 * the next filter — headers_out stays mutable and nothing reaches the
 * client. Upstream keeps feeding the body filter; we copy each buf into
 * pool-owned memory (upstream reuses its buffers once consumed) until
 * last_buf, then dispatch a NOTIFY and release on verdict/timeout.
 */


static ngx_http_output_header_filter_pt ngx_http_xngin_next_header;
static ngx_http_output_body_filter_pt   ngx_http_xngin_next_body;


static void    ngx_http_xngin_resp_timeout(ngx_event_t *ev);
static ngx_int_t ngx_http_xngin_resp_dispatch(ngx_http_xngin_ctx_t *rctx);
static void    ngx_http_xngin_resp_fail(ngx_http_xngin_ctx_t *rctx,
                   const char *err);
static ngx_int_t ngx_http_xngin_resp_collect(ngx_http_request_t *r,
                   ngx_http_xngin_ctx_t *ctx, ngx_chain_t *in);


void
ngx_http_xngin_filters_init(void)
{
    ngx_http_xngin_next_header = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_xngin_header_filter;

    ngx_http_xngin_next_body = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_xngin_body_filter;
}


/* ---------- response header set/unset ---------- */

static void
ngx_http_xngin_res_hdr_unset_one(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i;

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == name->len
            && ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0)
        {
            h[i].hash = 0;
            h[i].key.len = 0;
        }
    }

    /* dedicated headers_out fields drive the wire form */
    if (name->len == sizeof("content-length") - 1
        && ngx_strncasecmp(name->data, (u_char *) "content-length",
                           name->len) == 0)
    {
        ngx_http_clear_content_length(r);

    } else if (name->len == sizeof("etag") - 1
               && ngx_strncasecmp(name->data, (u_char *) "etag",
                                  name->len) == 0)
    {
        ngx_http_clear_etag(r);

    } else if (name->len == sizeof("last-modified") - 1
               && ngx_strncasecmp(name->data, (u_char *) "last-modified",
                                  name->len) == 0)
    {
        ngx_http_clear_last_modified(r);
    }
}


static ngx_int_t
ngx_http_xngin_res_hdr_set_one(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h, *new;
    ngx_uint_t        i;
    u_char           *low;

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == name->len
            && ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0)
        {
            h[i].value.data = ngx_pnalloc(r->pool, value->len);
            if (h[i].value.data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(h[i].value.data, value->data, value->len);
            h[i].value.len = value->len;
            h[i].hash = 1;
            goto special;
        }
    }

    low = ngx_pnalloc(r->pool, name->len);
    if (low == NULL) {
        return NGX_ERROR;
    }

    new = ngx_list_push(&r->headers_out.headers);
    if (new == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(low, name->data, name->len);
    new->hash = 1;
    new->key.len = name->len;
    new->key.data = ngx_pnalloc(r->pool, name->len);
    if (new->key.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(new->key.data, name->data, name->len);
    new->value.len = value->len;
    new->value.data = ngx_pnalloc(r->pool, value->len);
    if (new->value.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(new->value.data, value->data, value->len);
    new->lowcase_key = low;

special:

    if (name->len == sizeof("content-length") - 1
        && ngx_strncasecmp(name->data, (u_char *) "content-length",
                           name->len) == 0)
    {
        off_t n = ngx_atoof(value->data, value->len);
        r->headers_out.content_length_n = (n == NGX_ERROR) ? -1 : n;

    } else if (name->len == sizeof("content-type") - 1
               && ngx_strncasecmp(name->data, (u_char *) "content-type",
                                  name->len) == 0)
    {
        r->headers_out.content_type = *value;
        r->headers_out.content_type_len = value->len;
    }

    return NGX_OK;
}


/* apply res_hdr_set + res_hdr_unset stored on ctx */
ngx_int_t
ngx_http_xngin_res_hdr_apply(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx)
{
    ngx_http_xngin_var_t  *kv;
    ngx_str_t             *name;
    ngx_uint_t             i;

    if (ctx->res_hdr_unset) {
        name = ctx->res_hdr_unset->elts;
        for (i = 0; i < ctx->res_hdr_unset->nelts; i++) {
            ngx_http_xngin_res_hdr_unset_one(r, &name[i]);
        }
    }

    if (ctx->res_hdr_set) {
        kv = ctx->res_hdr_set->elts;
        for (i = 0; i < ctx->res_hdr_set->nelts; i++) {
            ngx_http_xngin_res_hdr_set_one(r, &kv[i].name, &kv[i].value);
        }
    }

    return NGX_OK;
}


/* ---------- release: emit held/replacement response ---------- */

/*
 * resp_release emits the response the agent (or fail policy) decided on.
 * `body` is the chain to send; verdict-time res-* ops on the parent ctx
 * are applied here so every release path behaves the same.
 */
void
ngx_http_xngin_resp_release(ngx_http_xngin_ctx_t *ctx, ngx_chain_t *body)
{
    ngx_http_request_t *r = ctx->r;

    if (ctx->resp_sent) {
        return;
    }

    ctx->resp_hold = 0;
    ctx->resp_sent = 1;
    ctx->res_done = 1;   /* stray filter calls must not re-emit res_body */

    ngx_http_xngin_res_hdr_apply(r, ctx);

    if (ctx->res_body_set) {
        ngx_http_clear_content_length(r);
        ngx_http_clear_etag(r);
    }

    if (body == NULL) {
        body = ctx->resp_held;
    }

    r->buffered &= ~NGX_HTTP_XNGIN_BUFFERED;

    ngx_http_xngin_next_header(r);
    ngx_http_xngin_next_body(r, body);
}


/*
 * async completion: emit the release, then re-run request finalization.
 * Upstream already ran ngx_http_finalize_request once — our buffered bit
 * diverted it into ngx_http_set_write_handler, so the request is still
 * alive and waiting.  With the bit cleared, this completes it (or re-arms
 * the writer when c->buffered still holds unsent bytes).
 */
static void
ngx_http_xngin_resp_finish(ngx_http_xngin_ctx_t *ctx)
{
    ngx_http_request_t *r = ctx->r;

    if (!ctx->resp_body_done) {
        /* early outcome while upstream is still delivering: releasing
           the held prefix (or deny body) is enough — upstream keeps
           running and its own finalize completes the request later */
        return;
    }

    ngx_http_finalize_request(r, NGX_OK);
}


/* single memory buf around s */
static ngx_chain_t *
ngx_http_xngin_mem_chain(ngx_http_request_t *r, ngx_str_t *s)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    b = ngx_calloc_buf(r->pool);
    cl = ngx_alloc_chain_link(r->pool);
    if (b == NULL || cl == NULL) {
        return NULL;
    }

    if (s && s->len) {
        b->pos = s->data;
        b->last = s->data + s->len;
        b->memory = 1;
    }

    b->last_buf = 1;
    b->last_in_chain = 1;

    cl->buf = b;
    cl->next = NULL;

    return cl;
}


/* ---------- header filter ---------- */

static ngx_int_t
ngx_http_xngin_resp_eligible(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx, ngx_http_xngin_loc_conf_t *lcf)
{
    if (ctx->resp_ctx || ctx->res_body_set || r->header_only) {
        return 0;
    }

    if (r->headers_out.status < NGX_HTTP_OK
        || r->headers_out.status == NGX_HTTP_NO_CONTENT
        || r->headers_out.status == NGX_HTTP_NOT_MODIFIED)
    {
        return 0;
    }

    /* declared length already over the cap: no inspection at all */
    if (r->headers_out.content_length_n > (off_t) lcf->res_body_max) {
        return 0;
    }

    /* only responses that came from an upstream */
    if (r->upstream == NULL || lcf->group == NULL) {
        return 0;
    }

    /* hold only if some ready conn negotiated RESP */
    return ngx_http_xngin_conn_pick_caps(lcf->group, XNAP_CAP_RESP) != NULL;
}


/* spawn the response-inspection stream ctx + timer */
static ngx_http_xngin_ctx_t *
ngx_http_xngin_resp_ctx_new(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx)
{
    ngx_http_xngin_ctx_t *rctx;

    rctx = ngx_pcalloc(r->pool, sizeof(ngx_http_xngin_ctx_t));
    if (rctx == NULL) {
        return NULL;
    }

    rctx->is_resp = 1;
    rctx->parent = ctx;
    rctx->r = r;

    rctx->timer = ngx_pcalloc(r->pool, sizeof(ngx_event_t));
    if (rctx->timer == NULL) {
        return NULL;
    }
    rctx->timer->handler = ngx_http_xngin_resp_timeout;
    rctx->timer->data = rctx;
    rctx->timer->log = r->connection->log;

    ctx->resp_ctx = rctx;
    return rctx;
}


ngx_int_t
ngx_http_xngin_header_filter(ngx_http_request_t *r)
{
    ngx_http_xngin_ctx_t      *ctx, *rctx;
    ngx_http_xngin_loc_conf_t *lcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xngin_module);

    if (ctx == NULL || r != r->main) {
        return ngx_http_xngin_next_header(r);
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xngin_module);

    if (lcf->response && !ctx->resp_sent
        && ngx_http_xngin_resp_eligible(r, ctx, lcf))
    {
        /*
         * Early dispatch: the http-response NOTIFY (headers + status)
         * goes out now; body frames stream through resp_collect as
         * chunks arrive — the agent analyzes while the response is
         * still downloading.  The held copy is kept for release/deny.
         */
        rctx = ngx_http_xngin_resp_ctx_new(r, ctx);
        if (rctx != NULL) {
            /* stream body frames only when a body is coming:
               CL > 0 or unknown (chunked); CL == 0 means none */
            rctx->body_stream = (r->headers_out.content_length_n != 0);
            if (ngx_http_xngin_resp_dispatch(rctx) != NGX_OK) {
                ctx->resp_ctx = NULL;
                rctx = NULL;
            }
        }

        if (rctx == NULL) {
            /* no agent stream: don't hold at all */
            ngx_http_xngin_res_hdr_apply(r, ctx);
            return ngx_http_xngin_next_header(r);
        }

        ctx->resp_hold = 1;
        ctx->resp_held_tail = &ctx->resp_held;
        r->buffered |= NGX_HTTP_XNGIN_BUFFERED;
        return NGX_OK;
    }

    ngx_http_xngin_res_hdr_apply(r, ctx);

    if (ctx->res_body_set) {
        ngx_http_clear_content_length(r);
        ngx_http_clear_etag(r);
    }

    return ngx_http_xngin_next_header(r);
}


/* ---------- body filter ---------- */

ngx_int_t
ngx_http_xngin_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_xngin_ctx_t *ctx;
    ngx_chain_t          *cl;
    ngx_chain_t          *out;
    ngx_int_t             rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xngin_module);

    if (ctx == NULL || r != r->main) {
        return ngx_http_xngin_next_body(r, in);
    }

    /* response round-trip buffering */
    if (ctx->resp_hold) {
        return ngx_http_xngin_resp_collect(r, ctx, in);
    }


    /* verdict-time res-body: swallow upstream body, emit replacement once */
    if (ctx->res_body_set) {
        for (cl = in; cl; cl = cl->next) {
            if (cl->buf) {
                cl->buf->pos = cl->buf->last;
            }
        }

        if (ctx->res_done) {
            return NGX_OK;
        }

        ctx->res_done = 1;

        out = ngx_http_xngin_mem_chain(r, &ctx->res_body);
        if (out == NULL) {
            return NGX_ERROR;
        }

        rc = ngx_http_xngin_next_body(r, out);
        ctx->resp_sent = 1;
        return rc;
    }

    return ngx_http_xngin_next_body(r, in);
}


/* ---------- http-response round-trip ---------- */

/* queue one response-body chunk as BODY frames on the open resp stream */
static void
ngx_http_xngin_resp_stream_send(ngx_http_xngin_ctx_t *rctx,
    u_char *pos, size_t len, unsigned last)
{
    ngx_http_xngin_conn_t *conn = rctx->conn;
    size_t                 chunk_max, n;
    uint32_t               flags;

    chunk_max = conn->max_frame;
    chunk_max = (chunk_max > 64) ? chunk_max - 32 : chunk_max;

    if (len == 0) {
        if (last) {
            ngx_http_xngin_conn_queue(conn, XNAP_FRAME_BODY,
                                      XNAP_FL_BODY_LAST,
                                      rctx->stream_id, rctx->frame_id++,
                                      NULL, 0);
        }
        return;
    }

    while (len) {
        n = (len > chunk_max) ? chunk_max : len;
        flags = (last && n == len) ? XNAP_FL_BODY_LAST : 0;

        if (ngx_http_xngin_conn_queue(conn, XNAP_FRAME_BODY, flags,
                                      rctx->stream_id, rctx->frame_id++,
                                      pos, n)
            != NGX_OK)
        {
            return;   /* conn_failed resolves the stream */
        }

        pos += n;
        len -= n;
    }
}


static ngx_int_t
ngx_http_xngin_resp_collect(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_http_xngin_ctx_t      *rctx;
    ngx_http_xngin_loc_conf_t *lcf;
    ngx_chain_t               *cl, *nl;
    ngx_buf_t                 *nb;
    u_char                    *data;
    size_t                     n;
    unsigned                   last = 0, send_last = 0;

    if (ctx->resp_pass) {
        return ngx_http_xngin_next_body(r, in);
    }

    rctx = ctx->resp_ctx;

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf == NULL) {
            continue;
        }

        n = cl->buf->last - cl->buf->pos;

        if (n == 0) {
            /*
             * empty buf: drop it, unless it carries the terminal flags —
             * upstream often sends last_buf as a standalone empty marker,
             * and without it the write filter postpones the held chain
             * (size < postpone_output) and nothing ever reaches the wire.
             */
            if (cl->buf->last_buf || cl->buf->last_in_chain) {
                nb = ngx_calloc_buf(r->pool);
                nl = ngx_alloc_chain_link(r->pool);
                if (nb == NULL || nl == NULL) {
                    return NGX_ERROR;
                }
                nb->last_buf = cl->buf->last_buf;
                nb->last_in_chain = cl->buf->last_in_chain;
                nl->buf = nb;
                nl->next = NULL;
                *ctx->resp_held_tail = nl;
                ctx->resp_held_tail = &nl->next;
                last = 1;
                send_last = 1;   /* body ends without trailing data */
            }
            continue;
        }

        nb = ngx_calloc_buf(r->pool);
        nl = ngx_alloc_chain_link(r->pool);
        data = ngx_pnalloc(r->pool, n);

        if (nb == NULL || nl == NULL || data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(data, cl->buf->pos, n);
        nb->pos = data;
        nb->last = data + n;
        nb->memory = 1;
        nb->last_buf = cl->buf->last_buf;
        nb->last_in_chain = cl->buf->last_in_chain;

        nl->buf = nb;
        nl->next = NULL;
        *ctx->resp_held_tail = nl;
        ctx->resp_held_tail = &nl->next;
        ctx->resp_held_len += n;

        /* stream this chunk to the agent while the download continues */
        if (rctx != NULL && rctx->body_stream && rctx->conn != NULL) {
            ngx_http_xngin_resp_stream_send(rctx, data, n,
                nb->last_buf || nb->last_in_chain);
        }

        cl->buf->pos = cl->buf->last;   /* consumed */

        if (nb->last_buf || nb->last_in_chain) {
            last = 1;
        }
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xngin_module);

    if (ctx->resp_held_len > lcf->res_body_max) {
        /*
         * cap hit on an undeclared-length body: release everything held,
         * pass through the rest.  Every buf in "in" was already consumed
         * into resp_held, so we must NOT forward it (zero-size
         * non-special bufs error the write filter); if this "in" ended
         * the response, carry the terminal flag on a special empty buf
         * appended to held.
         */
        if (last) {
            nb = ngx_calloc_buf(r->pool);
            nl = ngx_alloc_chain_link(r->pool);
            if (nb == NULL || nl == NULL) {
                return NGX_ERROR;
            }
            nb->last_buf = 1;
            nb->last_in_chain = 1;
            nl->buf = nb;
            nl->next = NULL;
            *ctx->resp_held_tail = nl;
            ctx->resp_held_tail = &nl->next;
        }

        /* the agent saw a partial stream: close it out */
        if (rctx != NULL && rctx->conn != NULL) {
            ngx_http_xngin_conn_send(rctx->conn, XNAP_FRAME_ABORT, 0,
                                   rctx->stream_id, rctx->frame_id++,
                                   NULL, 0);
            ngx_http_xngin_stream_del(rctx->conn, rctx->stream_id);
            rctx->conn = NULL;
        }
        if (rctx != NULL) {
            rctx->body_stream = 0;
        }

        ctx->resp_pass = 1;
        r->buffered &= ~NGX_HTTP_XNGIN_BUFFERED;
        ngx_http_xngin_resp_release(ctx, ctx->resp_held);
        return NGX_OK;
    }

    if (!last) {
        if (rctx != NULL && rctx->body_stream && rctx->conn != NULL) {
            ngx_http_xngin_conn_flush_conn(rctx->conn);
        }
        return NGX_OK;
    }

    /* body complete: the stream is fully delivered */
    ctx->resp_body_done = 1;

    if (rctx != NULL && rctx->body_stream && rctx->conn != NULL) {
        if (send_last) {
            /* the final buf carried no data — the LAST flag still
               has to reach the agent */
            ngx_http_xngin_resp_stream_send(rctx, NULL, 0, 1);
        }
        ngx_http_xngin_conn_flush_conn(rctx->conn);
    }
    if (rctx != NULL) {
        rctx->body_stream = 0;
    }

    if (rctx == NULL) {
        /* dispatch failed at header time: nothing held should exist,
           but release defensively */
        ngx_http_xngin_resp_release(ctx, ctx->resp_held);
        return NGX_OK;
    }

    if (rctx->stream_failed) {
        /* conn died / timed out mid-download; the body is fully
           buffered now, so the fail policy can run safely */
        ngx_http_xngin_resp_fail(rctx, "down");
        return NGX_OK;
    }

    if (rctx->state == XNAP_ST_DONE) {
        /* early verdict already handled release/deny */
        return NGX_OK;
    }

    if (rctx->conn != NULL && !rctx->timer->timer_set) {
        ngx_add_timer(rctx->timer, lcf->timeout);
    }

    return NGX_OK;
}


/* build the http-response NOTIFY payload; body_len is the declared
   Content-Length (>0), 0 when none/unknown */
static ngx_int_t
ngx_http_xngin_resp_notify(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx, ngx_xnap_wbuf_t *wb, off_t body_len)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i;
    ngx_xnap_wbuf_t   hdrs;
    ngx_str_t         msg = ngx_string("http-response");
    u_char            vbuf[8], *v;

    if (ngx_xnap_wbuf_varint(wb, msg.len) != NGX_OK
        || ngx_xnap_wbuf_bytes(wb, msg.data, msg.len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_xnap_wbuf_kv_name(wb, "status");
    ngx_xnap_wbuf_u8(wb, XNAP_VT_UINT32);
    ngx_xnap_wbuf_varint(wb, r->headers_out.status);

    v = ngx_snprintf(vbuf, sizeof(vbuf), "%d.%d",
                     r->http_major, r->http_minor);
    ngx_xnap_wbuf_kv_str(wb, "http-version", vbuf, v - vbuf);

    ngx_xnap_wbuf_kv_str(wb, "method",
                       r->method_name.data, r->method_name.len);
    ngx_xnap_wbuf_kv_str(wb, "uri", r->unparsed_uri.data,
                       r->unparsed_uri.len);

    if (ctx->request_id.len) {
        ngx_xnap_wbuf_kv_str(wb, "request-id", ctx->request_id.data,
                           ctx->request_id.len);
    }

    if (r->connection->sockaddr->sa_family == AF_INET
#if (NGX_HAVE_INET6)
        || r->connection->sockaddr->sa_family == AF_INET6
#endif
        )
    {
        ngx_xnap_wbuf_kv_ip(wb, "src-ip", r->connection->sockaddr);
    }

    /* response headers as a KVL, lower-cased names */
    ngx_xnap_wbuf_init(&hdrs, r->pool, 1024);

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0 || h[i].key.len == 0) {
            continue;
        }

        ngx_xnap_wbuf_varint(&hdrs, h[i].key.len);
        ngx_xnap_wbuf_bytes(&hdrs,
                            h[i].lowcase_key ? h[i].lowcase_key
                                             : h[i].key.data,
                            h[i].key.len);
        ngx_xnap_wbuf_u8(&hdrs, XNAP_VT_STR);
        ngx_xnap_wbuf_varint(&hdrs, h[i].value.len);
        ngx_xnap_wbuf_bytes(&hdrs, h[i].value.data, h[i].value.len);
    }

    ngx_xnap_wbuf_kv_name(wb, "headers");
    ngx_xnap_wbuf_u8(wb, XNAP_VT_KVL);
    ngx_xnap_wbuf_varint(wb, hdrs.pos - hdrs.start);
    ngx_xnap_wbuf_bytes(wb, hdrs.start, hdrs.pos - hdrs.start);

    if (body_len > 0) {
        ngx_xnap_wbuf_kv_name(wb, "body-len");
        ngx_xnap_wbuf_u8(wb, XNAP_VT_UINT32);
        ngx_xnap_wbuf_varint(wb, body_len);
    }

    return NGX_OK;
}


/* stream the held body to the agent as chunked BODY frames */
static ngx_int_t
ngx_http_xngin_resp_send_body(ngx_http_xngin_ctx_t *rctx)
{
    ngx_http_xngin_ctx_t  *ctx = rctx->parent;
    ngx_chain_t           *cl;
    size_t                 chunk_max, n, remaining;
    u_char                *pos;
    uint32_t               flags;

    chunk_max = rctx->conn->max_frame;
    chunk_max = (chunk_max > 64) ? chunk_max - 32 : chunk_max;

    remaining = ctx->resp_held_len;

    for (cl = ctx->resp_held; cl && remaining; cl = cl->next) {
        pos = cl->buf->pos;

        while (pos < cl->buf->last) {
            n = cl->buf->last - pos;
            if (n > chunk_max) {
                n = chunk_max;
            }
            remaining -= n;
            flags = remaining ? 0 : XNAP_FL_BODY_LAST;

            if (ngx_http_xngin_conn_send(rctx->conn, XNAP_FRAME_BODY, flags,
                                         rctx->stream_id, rctx->frame_id++,
                                         pos, n)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            pos += n;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_resp_dispatch(ngx_http_xngin_ctx_t *rctx)
{
    ngx_http_request_t        *r = rctx->r;
    ngx_http_xngin_ctx_t      *ctx = rctx->parent;
    ngx_http_xngin_loc_conf_t *lcf;
    ngx_http_xngin_conn_t     *conn;
    ngx_xnap_wbuf_t            wb;
    uint32_t                   flags = 0;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xngin_module);

    conn = ngx_http_xngin_conn_pick_caps(lcf->group, XNAP_CAP_RESP);
    if (conn == NULL) {
        return NGX_BUSY;
    }

    rctx->conn = conn;
    rctx->stream_id = conn->next_sid;
    conn->next_sid += 2;
    rctx->frame_id = 0;

    ngx_xnap_wbuf_init(&wb, r->pool, 2048);
    if (ngx_http_xngin_resp_notify(r, ctx, &wb,
                                   rctx->body_stream
                                   ? r->headers_out.content_length_n
                                   : (off_t) ctx->resp_held_len)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (rctx->body_stream || ctx->resp_held_len) {
        flags |= XNAP_FL_NOTIFY_HAS_BODY;
    }

    ngx_http_xngin_stream_add(conn, rctx->stream_id, rctx);

    if (ngx_http_xngin_conn_queue(conn, XNAP_FRAME_NOTIFY, flags,
                                 rctx->stream_id, rctx->frame_id++,
                                 wb.start, wb.pos - wb.start)
        != NGX_OK)
    {
        ngx_http_xngin_stream_del(conn, rctx->stream_id);
        rctx->conn = NULL;
        return NGX_ERROR;
    }

    if (!rctx->body_stream && ctx->resp_held_len
        && ngx_http_xngin_resp_send_body(rctx) != NGX_OK)
    {
        ngx_http_xngin_stream_del(conn, rctx->stream_id);
        rctx->conn = NULL;
        return NGX_ERROR;
    }

    ngx_http_xngin_conn_flush_conn(conn);

    rctx->state = XNAP_ST_SENT;
    rctx->sent_at = ngx_http_xngin_now_us();

    /* for streamed bodies the verdict wait starts when the LAST frame
       goes out (resp_collect arms the timer there) */
    if (!rctx->body_stream) {
        ngx_add_timer(rctx->timer, lcf->timeout);
    }

    return NGX_OK;
}


static void
ngx_http_xngin_resp_timeout(ngx_event_t *ev)
{
    ngx_http_xngin_ctx_t *rctx = ev->data;

    if (rctx->state != XNAP_ST_SENT) {
        return;
    }

    rctx->state = XNAP_ST_TIMEDOUT;

    if (rctx->body_stream) {
        /* response still downloading — the verdict wait hasn't really
           started; defer to last_buf in resp_collect */
        if (rctx->conn) {
            ngx_http_xngin_conn_send(rctx->conn, XNAP_FRAME_ABORT, 0,
                                     rctx->stream_id, rctx->frame_id++,
                                     NULL, 0);
            ngx_http_xngin_stream_del(rctx->conn, rctx->stream_id);
            rctx->conn = NULL;
        }
        rctx->body_stream = 0;
        rctx->stream_failed = 1;
        return;
    }

    if (rctx->conn) {
        ngx_http_xngin_conn_send(rctx->conn, XNAP_FRAME_ABORT, 0,
                                 rctx->stream_id, rctx->frame_id++, NULL, 0);
        ngx_http_xngin_stream_del(rctx->conn, rctx->stream_id);
        rctx->conn = NULL;
    }

    if (!rctx->retried) {
        rctx->retried = 1;
        if (ngx_http_xngin_resp_dispatch(rctx) == NGX_OK) {
            return;
        }
    }

    ngx_http_xngin_resp_fail(rctx, "timeout");
}


void
ngx_http_xngin_resp_conn_failed(ngx_http_xngin_ctx_t *rctx)
{
    rctx->conn = NULL;

    if (rctx->state != XNAP_ST_SENT) {
        return;
    }

    if (rctx->body_stream) {
        /* mid-download: held bytes can't be replayed mid-flight on a
           new stream; defer to resp_collect's completion path */
        rctx->body_stream = 0;
        rctx->stream_failed = 1;
        return;
    }

    if (!rctx->retried) {
        rctx->retried = 1;
        if (ngx_http_xngin_resp_dispatch(rctx) == NGX_OK) {
            return;
        }
    }

    ngx_http_xngin_resp_fail(rctx, "down");
}


/* fail policy on the response path */
static void
ngx_http_xngin_resp_fail(ngx_http_xngin_ctx_t *rctx, const char *err)
{
    ngx_http_xngin_ctx_t      *ctx = rctx->parent;
    ngx_http_request_t        *r = ctx->r;
    ngx_http_xngin_loc_conf_t *lcf;
    ngx_str_t                  body;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xngin_module);

    if (rctx->timer && rctx->timer->timer_set) {
        ngx_del_timer(rctx->timer);
    }

    rctx->state = XNAP_ST_DONE;
    rctx->error.data = (u_char *) err;
    rctx->error.len = ngx_strlen(err);
    ctx->error = rctx->error;

    if (lcf->fail == XNAP_FAIL_OPEN) {
        ngx_http_xngin_resp_release(ctx, ctx->resp_held);
        ngx_http_xngin_resp_finish(ctx);
        return;
    }

    /* headers never reached the wire: same fail-close reply as the
       request path (503) */
    r->headers_out.status = NGX_HTTP_SERVICE_UNAVAILABLE;
    r->headers_out.status_line.len = 0;
    r->headers_out.status_line.data = NULL;
    ngx_str_set(&body, "503 Service Unavailable\n");

    ctx->res_body_set = 1;   /* release path clears C-L/ETag */
    ngx_http_xngin_resp_release(ctx,
        ngx_http_xngin_mem_chain(r, &body));
    ngx_http_xngin_resp_finish(ctx);
}


/* verdict on an http-response stream */
ngx_int_t
ngx_http_xngin_resp_verdict(ngx_http_xngin_conn_t *c,
    ngx_http_xngin_ctx_t *rctx, u_char *payload, size_t len)
{
    ngx_http_request_t     *r;
    ngx_http_xngin_ctx_t   *ctx;
    ngx_xnap_rbuf_t         rb;
    ngx_str_t               name;
    ngx_xnap_val_t          v;
    ngx_str_t               action = ngx_null_string;
    ngx_int_t               status = 0;
    ngx_str_t               body = ngx_null_string;
    ngx_str_t               ctype = ngx_null_string;
    ngx_str_t               res_body = ngx_null_string;
    ngx_str_t               reason = ngx_null_string;
    ngx_int_t               rc;
    ngx_chain_t            *out;

    if (rctx->state != XNAP_ST_SENT) {
        return NGX_OK;
    }

    ctx = rctx->parent;
    r = ctx->r;

    rctx->agent_rtt = ngx_http_xngin_now_us() - rctx->sent_at;
    ctx->agent_rtt = rctx->agent_rtt;

    ngx_http_xngin_stream_del(c, rctx->stream_id);
    rctx->conn = NULL;
    rctx->state = XNAP_ST_DONE;
    rctx->body_stream = 0;

    if (rctx->timer && rctx->timer->timer_set) {
        ngx_del_timer(rctx->timer);
    }

    rb.pos = payload;
    rb.end = payload + len;
    rb.err = 0;

    while ((rc = ngx_xnap_rbuf_kv(&rb, &name, &v)) == NGX_OK) {

        if (name.len == 6 && ngx_memcmp(name.data, "action", 6) == 0) {
            action.data = ngx_pnalloc(r->pool, v.s.len);
            ngx_memcpy(action.data, v.s.data, v.s.len);
            action.len = v.s.len;
        }
        else if (name.len == 6 && ngx_memcmp(name.data, "status", 6) == 0) {
            status = (ngx_int_t) v.i;
        }
        else if (name.len == 4 && ngx_memcmp(name.data, "body", 4) == 0) {
            body.data = ngx_pnalloc(r->pool, v.s.len);
            ngx_memcpy(body.data, v.s.data, v.s.len);
            body.len = v.s.len;
        }
        else if (name.len == 12
                 && ngx_memcmp(name.data, "content-type", 12) == 0)
        {
            ctype.data = ngx_pnalloc(r->pool, v.s.len);
            ngx_memcpy(ctype.data, v.s.data, v.s.len);
            ctype.len = v.s.len;
        }
        else if (name.len == 11
                 && ngx_memcmp(name.data, "res-hdr-set", 11) == 0)
        {
            ngx_http_xngin_parse_res_hdr_set(r, rctx, v.sub, v.sub_len);
        }
        else if (name.len == 13
                 && ngx_memcmp(name.data, "res-hdr-unset", 13) == 0)
        {
            ngx_http_xngin_parse_res_hdr_unset(r, rctx, v.sub, v.sub_len,
                                               v.u);
        }
        else if (name.len == 8
                 && ngx_memcmp(name.data, "res-body", 8) == 0)
        {
            res_body.data = ngx_pnalloc(r->pool, v.s.len);
            ngx_memcpy(res_body.data, v.s.data, v.s.len);
            res_body.len = v.s.len;
        }
        else if (name.len == 4 && ngx_memcmp(name.data, "vars", 4) == 0) {
            /* response vars land on the parent ctx → $xngin_<name> */
            ngx_http_xngin_parse_vars(r, ctx, v.sub, v.sub_len);
        }
        else if (name.len == 6 && ngx_memcmp(name.data, "reason", 6) == 0) {
            reason.data = ngx_pnalloc(r->pool, v.s.len);
            ngx_memcpy(reason.data, v.s.data, v.s.len);
            reason.len = v.s.len;
            ctx->reason = reason;
        }
        else if (name.len == 5 && ngx_memcmp(name.data, "score", 5) == 0) {
            ctx->score = v.i;
        }
    }

    /* resp verdict res-hdr ops apply first, parent's second (parent wins
       on conflict — it was the request-time decision) */
    ngx_http_xngin_res_hdr_apply(r, rctx);

    if (action.len == 4 && ngx_memcmp(action.data, "deny", 4) == 0) {
        r->headers_out.status = (status >= 400 && status < 600)
                                ? status : NGX_HTTP_FORBIDDEN;
        r->headers_out.status_line.len = 0;   /* regenerate status line */
        r->headers_out.status_line.data = NULL;

        if (ctype.len) {
            ngx_str_t ctn = ngx_string("content-type");
            ngx_http_xngin_res_hdr_set_one(r, &ctn, &ctype);
        }

        out = ngx_http_xngin_mem_chain(r, &body);
        if (out == NULL) {
            return NGX_ERROR;
        }

        ctx->res_body_set = 1;   /* release path clears C-L/ETag */
        ngx_http_xngin_resp_release(ctx, out);
        ngx_http_xngin_resp_finish(ctx);
        return NGX_OK;
    }

    if (action.len != 5 || ngx_memcmp(action.data, "allow", 5) != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xngin: malformed resp verdict action \"%V\"", &action);
        ngx_http_xngin_resp_fail(rctx, "proto");
        return NGX_OK;
    }

    /* allow: optional status override / res-body replacement */
    if (status >= 200 && status < 600) {
        r->headers_out.status = status;
        r->headers_out.status_line.len = 0;
        r->headers_out.status_line.data = NULL;
    }

    if (res_body.data) {
        ctx->res_body = res_body;
        ctx->res_body_set = 1;
        out = ngx_http_xngin_mem_chain(r, &res_body);
    } else {
        out = ctx->resp_held;
    }

    if (out == NULL) {
        return NGX_ERROR;
    }

    ngx_http_xngin_resp_release(ctx, out);
    ngx_http_xngin_resp_finish(ctx);

    return NGX_OK;
}


/* abort any in-flight resp stream (request cleanup path) */
void
ngx_http_xngin_resp_abort(ngx_http_xngin_ctx_t *ctx)
{
    ngx_http_xngin_ctx_t *rctx = ctx->resp_ctx;

    if (rctx == NULL) {
        return;
    }

    if (rctx->timer && rctx->timer->timer_set) {
        ngx_del_timer(rctx->timer);
    }

    if (rctx->conn && rctx->state == XNAP_ST_SENT) {
        ngx_http_xngin_conn_send(rctx->conn, XNAP_FRAME_ABORT,
                                 0, rctx->stream_id, rctx->frame_id++,
                                 NULL, 0);
    }

    if (rctx->conn) {
        ngx_http_xngin_stream_del(rctx->conn, rctx->stream_id);
    }

    rctx->state = XNAP_ST_ABORTED;
    rctx->conn = NULL;
    ctx->resp_ctx = NULL;
}
