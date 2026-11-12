#include "ngx_http_xngin_module.h"


static void  ngx_http_xngin_fail(ngx_http_xngin_ctx_t *ctx,
                const char *err);
static ngx_int_t ngx_http_xngin_body_in_mem(ngx_http_request_t *r);
static ngx_int_t ngx_http_xngin_hdr_set(ngx_http_request_t *r,
                ngx_str_t *name, ngx_str_t *value);
static void  ngx_http_xngin_hdr_unset(ngx_http_request_t *r,
                ngx_str_t *name);
void         ngx_http_xngin_apply_req_body(ngx_http_request_t *r,
                ngx_http_xngin_ctx_t *ctx);


/* ---------- NOTIFY construction ---------- */

ngx_int_t
ngx_http_xngin_build_notify(ngx_http_request_t *r, ngx_http_xngin_ctx_t *ctx,
    ngx_xnap_wbuf_t *wb)
{
    ngx_list_part_t        *part;
    ngx_table_elt_t        *h;
    ngx_uint_t              i;
    ngx_xnap_wbuf_t         hdrs;
    struct sockaddr        *sa;

    /* message name */
    ngx_str_t msg = ngx_string("http-request");
    if (ngx_xnap_wbuf_varint(wb, msg.len) != NGX_OK
        || ngx_xnap_wbuf_bytes(wb, msg.data, msg.len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_xnap_wbuf_kv_str(wb, "method",
                       r->method_name.data, r->method_name.len);
    ngx_xnap_wbuf_kv_str(wb, "scheme",
                       r->schema.data, r->schema.len);

    if (r->headers_in.host) {
        ngx_xnap_wbuf_kv_str(wb, "host",
                             r->headers_in.host->value.data,
                             r->headers_in.host->value.len);
    }

    ngx_xnap_wbuf_kv_str(wb, "uri", r->unparsed_uri.data,
                       r->unparsed_uri.len);

    /* http-version */
    {
        u_char vbuf[8];
        u_char *v = ngx_snprintf(vbuf, sizeof(vbuf), "%d.%d",
                                 r->http_major, r->http_minor);
        ngx_xnap_wbuf_kv_str(wb, "http-version", vbuf, v - vbuf);
    }

    /* headers as nested KVL */
    ngx_xnap_wbuf_init(&hdrs, r->pool, 1024);

    part = &r->headers_in.headers.part;
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

        if (h[i].hash == 0) {
            continue;
        }

        ngx_xnap_wbuf_varint(&hdrs, h[i].lowcase_key
                             ? h[i].key.len : h[i].key.len);
        ngx_xnap_wbuf_bytes(&hdrs,
                            h[i].lowcase_key ? h[i].lowcase_key
                                             : h[i].key.data,
                            h[i].key.len);
        ngx_xnap_wbuf_u8(&hdrs, XNAP_VT_STR);
        ngx_xnap_wbuf_varint(&hdrs, h[i].value.len);
        ngx_xnap_wbuf_bytes(&hdrs, h[i].value.data, h[i].value.len);
    }

    /* emit "headers" KVL value */
    ngx_xnap_wbuf_kv_name(wb, "headers");
    ngx_xnap_wbuf_u8(wb, XNAP_VT_KVL);
    ngx_xnap_wbuf_varint(wb, hdrs.pos - hdrs.start);
    ngx_xnap_wbuf_bytes(wb, hdrs.start, hdrs.pos - hdrs.start);

    /* connection info */
    ngx_xnap_wbuf_kv_ip(wb, "src-ip", r->connection->sockaddr);
    ngx_xnap_wbuf_kv_uint(wb, "src-port",
                          ngx_inet_get_port(r->connection->sockaddr));

    sa = r->connection->local_sockaddr;
    if (sa) {
        ngx_xnap_wbuf_kv_ip(wb, "dst-ip", sa);
        ngx_xnap_wbuf_kv_uint(wb, "dst-port", ngx_inet_get_port(sa));
    }

#if (NGX_SSL)
    {
        SSL *ssl = r->connection->ssl ? r->connection->ssl->connection : NULL;

        ngx_xnap_wbuf_kv_bool(wb, "tls",
                              r->connection->ssl != NULL
                              && r->connection->ssl->handshaked);

        if (ssl && r->connection->ssl->handshaked) {
            const char           *ver;
            const char           *sni;
            const unsigned char  *alpn = NULL;
            unsigned int          alpn_len = 0;

            ver = SSL_get_version(ssl);
            ngx_xnap_wbuf_kv_str(wb, "tls-version", ver, ngx_strlen(ver));

            sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
            if (sni) {
                ngx_xnap_wbuf_kv_str(wb, "sni", sni, ngx_strlen(sni));
            }

            SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
            if (alpn && alpn_len) {
                ngx_xnap_wbuf_kv_str(wb, "alpn", alpn, alpn_len);
            }
        }

        {
            ngx_http_xngin_hello_t *hello;

            hello = ngx_http_xngin_tls_hello(r->connection);
            if (hello) {
                if (hello->ja4.len) {
                    ngx_xnap_wbuf_kv_str(wb, "ja4", hello->ja4.data,
                                         hello->ja4.len);
                }
                if (hello->ch_raw.len) {
                    ngx_xnap_wbuf_kv_name(wb, "ch-raw");
                    ngx_xnap_wbuf_u8(wb, XNAP_VT_BIN);
                    ngx_xnap_wbuf_varint(wb, hello->ch_raw.len);
                    ngx_xnap_wbuf_bytes(wb, hello->ch_raw.data,
                                        hello->ch_raw.len);
                }
            }
        }
    }
#else
    ngx_xnap_wbuf_kv_bool(wb, "tls", 0);
#endif

    /* request-id: nginx>=1.31 generates $request_id lazily, so we
       synthesize our own correlation id: conn number + per-worker seq */
    {
        u_char           idb[32];
        ngx_str_t        id;
        static ngx_uint_t seq;

        id.data = idb;
        id.len = ngx_snprintf(idb, sizeof(idb), "%uAi-%ui",
                              r->connection->number, ++seq) - idb;
        ngx_xnap_wbuf_kv_str(wb, "request-id", id.data, id.len);

        if (ctx && ctx->request_id.data == NULL) {
            ctx->request_id.data = ngx_pnalloc(r->pool, id.len);
            if (ctx->request_id.data) {
                ngx_memcpy(ctx->request_id.data, id.data, id.len);
                ctx->request_id.len = id.len;
            }
        }
    }

    if (r->headers_in.content_length_n > 0) {
        ngx_xnap_wbuf_kv_uint(wb, "body-len",
                              (uint64_t) r->headers_in.content_length_n);
    }

    {
        ngx_http_xngin_loc_conf_t *lcf;
        unsigned has_body;

        lcf = ngx_http_get_module_loc_conf(r, ngx_http_xngin_module);
        has_body = ngx_http_xngin_body_in_mem(r);

        if (lcf->body_inspect
            && (r->headers_in.content_length_n > 0 || r->headers_in.chunked)
            && !has_body)
        {
            /* body exists but was not captured */
            ngx_xnap_wbuf_kv_bool(wb, "body-truncated", 1);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_body_in_mem(ngx_http_request_t *r)
{
    ngx_http_request_body_t *rb = r->request_body;
    ngx_chain_t             *cl;

    if (rb == NULL) {
        return 0;
    }

    for (cl = rb->bufs; cl; cl = cl->next) {
        if (cl->buf && !cl->buf->in_file
            && cl->buf->last > cl->buf->pos)
        {
            return 1;
        }
    }

    if (rb->buf && !rb->buf->in_file && rb->buf->last > rb->buf->pos) {
        return 1;
    }

    return 0;
}


ngx_int_t
ngx_http_xngin_send_body(ngx_http_request_t *r, ngx_http_xngin_ctx_t *ctx)
{
    ngx_http_request_body_t *rb = r->request_body;
    ngx_chain_t             *cl;
    size_t                   chunk_max, n, remaining = 0;
    u_char                  *pos;
    uint32_t                 flags;

    if (rb == NULL) {
        return NGX_OK;
    }

    /* single contiguous buf: normalize into a one-link chain */
    if (rb->bufs == NULL) {
        if (rb->buf == NULL || rb->buf->in_file
            || rb->buf->last == rb->buf->pos)
        {
            return NGX_OK;
        }
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }
        cl->buf = rb->buf;
        cl->next = NULL;
        rb->bufs = cl;
    }

    /* count bytes so LAST lands on the final chunk */
    for (cl = rb->bufs; cl; cl = cl->next) {
        if (cl->buf && !cl->buf->in_file && cl->buf->last > cl->buf->pos) {
            remaining += cl->buf->last - cl->buf->pos;
        }
    }

    if (remaining == 0) {
        return NGX_OK;
    }

    /* frame payload must fit the negotiated max-frame-size */
    chunk_max = ctx->conn->max_frame;
    chunk_max = (chunk_max > 64) ? chunk_max - 32 : chunk_max;

    for (cl = rb->bufs; cl && remaining; cl = cl->next) {
        if (cl->buf == NULL || cl->buf->in_file
            || cl->buf->last == cl->buf->pos)
        {
            continue;
        }

        pos = cl->buf->pos;

        while (pos < cl->buf->last) {
            n = cl->buf->last - pos;
            if (n > chunk_max) {
                n = chunk_max;
            }
            remaining -= n;
            flags = remaining ? 0 : XNAP_FL_BODY_LAST;

            if (ngx_http_xngin_conn_queue(ctx->conn, XNAP_FRAME_BODY, flags,
                                          ctx->stream_id, ctx->frame_id++,
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


/* upper bound for the encoded NOTIFY payload — cheap over-estimate so
   the frame can be encoded straight into a send pkt without a staging
   copy; a miss just falls back to the pool wbuf + copy path */
static size_t
ngx_http_xngin_notify_bound(ngx_http_request_t *r)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i;
    size_t            bound = 1024;   /* fixed fields + TLS strings */

    bound += r->unparsed_uri.len + r->method_name.len + r->schema.len;
    if (r->headers_in.host) {
        bound += r->headers_in.host->value.len;
    }

    part = &r->headers_in.headers.part;
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
        if (h[i].hash == 0) {
            continue;
        }
        bound += h[i].key.len + h[i].value.len + 24;
    }

#if (NGX_SSL)
    if (r->connection->ssl && r->connection->ssl->handshaked) {
        ngx_http_xngin_hello_t *hello;

        bound += 256;   /* tls-version / sni / alpn strings */

        hello = ngx_http_xngin_tls_hello(r->connection);
        if (hello) {
            bound += hello->ja4.len + hello->ch_raw.len;
        }
    }
#endif

    return bound;
}


/* ---------- streaming request-body dispatch ---------- */

/*
 * Chained into ngx_http_top_request_body_filter (nginx >= 1.28).  Each
 * call hands us the body bytes nginx just read; while ctx->body_stream
 * is set we forward them as BODY frames on the already-open stream, so
 * the agent sees the request body as it arrives instead of after the
 * whole upload is buffered.  The data is memcpy'd into send pkts here,
 * so it is safe for the caller to recycle the chain afterwards.
 */

static ngx_http_request_body_filter_pt ngx_http_xngin_next_body_filter;

static ngx_int_t
ngx_http_xngin_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t               rc;
    ngx_chain_t            *cl;
    ngx_buf_t              *b;
    ngx_http_xngin_ctx_t   *ctx;
    ngx_http_xngin_conn_t  *conn;
    size_t                  chunk_max, n;
    u_char                 *pos;
    uint32_t                flags;
    unsigned                last;

    rc = ngx_http_xngin_next_body_filter(r, in);
    if (rc != NGX_OK) {
        return rc;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_xngin_module);
    if (ctx == NULL || !ctx->body_stream) {
        return rc;
    }

    conn = ctx->conn;
    if (conn == NULL) {
        return rc;   /* stream_failed: drain the upload, resolve later */
    }

    chunk_max = conn->max_frame;
    chunk_max = (chunk_max > 64) ? chunk_max - 32 : chunk_max;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;
        if (b == NULL || b->in_file) {
            continue;
        }

        last = b->last_buf && cl->next == NULL;
        pos = b->pos;

        if (pos == b->last) {
            if (last) {
                /* empty final buf: zero-length BODY carries LAST */
                if (ngx_http_xngin_conn_queue(conn, XNAP_FRAME_BODY,
                                              XNAP_FL_BODY_LAST,
                                              ctx->stream_id,
                                              ctx->frame_id++, NULL, 0)
                    != NGX_OK)
                {
                    return rc;
                }
                ctx->body_stream = 0;
            }
            continue;
        }

        while (pos < b->last) {
            n = b->last - pos;
            if (n > chunk_max) {
                n = chunk_max;
            }
            flags = (last && pos + n == b->last) ? XNAP_FL_BODY_LAST : 0;

            if (ngx_http_xngin_conn_queue(conn, XNAP_FRAME_BODY, flags,
                                          ctx->stream_id, ctx->frame_id++,
                                          pos, n)
                != NGX_OK)
            {
                return rc;   /* conn_failed will resolve the request */
            }

            if (flags & XNAP_FL_BODY_LAST) {
                ctx->body_stream = 0;
            }
            pos += n;
        }
    }

    ngx_http_xngin_conn_flush_conn(conn);

    return rc;
}


void
ngx_http_xngin_stream_filter_init(void)
{
    ngx_http_xngin_next_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_xngin_request_body_filter;
}


/* ---------- dispatch ---------- */

ngx_int_t
ngx_http_xngin_dispatch(ngx_http_request_t *r, ngx_http_xngin_ctx_t *ctx)
{
    ngx_http_xngin_loc_conf_t  *lcf;
    ngx_xnap_wbuf_t             wb;
    ngx_http_xngin_conn_t      *conn;
    ngx_xnap_pkt_t             *pkt;
    u_char                     *buf;
    size_t                      bound;
    uint32_t                    flags = 0;
    ngx_int_t                   rc;
    unsigned                    has_body = 0;
    unsigned                    sent_notify = 0;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xngin_module);

    conn = ngx_http_xngin_conn_pick(lcf->group);
    if (conn == NULL) {
        return NGX_BUSY;
    }

    has_body = lcf->body_inspect
               && (ctx->body_stream || ngx_http_xngin_body_in_mem(r));

    ctx->conn = conn;
    ctx->stream_id = conn->next_sid;
    conn->next_sid += 2;
    ctx->frame_id = 0;

    if (has_body) {
        flags |= XNAP_FL_NOTIFY_HAS_BODY;
    }
    if (ctx->async) {
        flags |= XNAP_FL_NOTIFY_ASYNC;
    }

    /* fast path: encode the NOTIFY straight into a send pkt — no
       staging buffer, no payload memcpy */
    bound = ngx_http_xngin_notify_bound(r);
    buf = ngx_http_xngin_conn_pkt_reserve(conn, bound, &pkt);
    if (buf) {
        ngx_xnap_wbuf_init_fixed(&wb, buf, buf + bound);
        if (ngx_http_xngin_build_notify(r, ctx, &wb) == NGX_OK) {
            ngx_http_xngin_stream_add(conn, ctx->stream_id, ctx);

            rc = ngx_http_xngin_conn_pkt_commit(conn, pkt,
                        XNAP_FRAME_NOTIFY, flags,
                        ctx->stream_id, ctx->frame_id++,
                        wb.pos - buf);
            if (rc == NGX_OK) {
                sent_notify = 1;
            } else {
                ngx_http_xngin_stream_del(conn, ctx->stream_id);
                ctx->conn = NULL;
                return rc;
            }
        } else {
            /* bound miss or encode error — retry via the pool path */
            ngx_http_xngin_pkt_discard(conn, pkt);
        }
    }

    if (!sent_notify) {
        ngx_xnap_wbuf_init(&wb, r->pool, 2048);
        if (ngx_http_xngin_build_notify(r, ctx, &wb) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_http_xngin_stream_add(conn, ctx->stream_id, ctx);

        rc = ngx_http_xngin_conn_queue(conn, XNAP_FRAME_NOTIFY, flags,
                                       ctx->stream_id, ctx->frame_id++,
                                       wb.start, wb.pos - wb.start);
        if (rc != NGX_OK) {
            ngx_http_xngin_stream_del(conn, ctx->stream_id);
            ctx->conn = NULL;
            return rc;
        }
    }

    if (has_body && !ctx->body_stream) {
        /* streaming dispatch sends BODY frames from the request body
           filter instead; send_body is the buffered/replay path */
        rc = ngx_http_xngin_send_body(r, ctx);
        if (rc != NGX_OK) {
            ngx_http_xngin_stream_del(conn, ctx->stream_id);
            ctx->conn = NULL;
            return rc;
        }
    }

    /* one writev for NOTIFY + all queued BODY frames */
    ngx_http_xngin_conn_flush_conn(conn);

    ctx->state = XNAP_ST_SENT;
    ctx->sent_at = ngx_http_xngin_now_us();

    return NGX_OK;
}


/* ---------- abort / cleanup ---------- */

void
ngx_http_xngin_ctx_abort(ngx_http_xngin_ctx_t *ctx)
{
    if (ctx->timer && ctx->timer->timer_set) {
        ngx_del_timer(ctx->timer);
    }

    if (ctx->resp_ctx) {
        ngx_http_xngin_resp_abort(ctx);
    }

    if (ctx->conn && ctx->state == XNAP_ST_SENT) {
        /* best-effort ABORT with empty payload */
        ngx_http_xngin_conn_send(ctx->conn, XNAP_FRAME_ABORT,
                                 0, ctx->stream_id, ctx->frame_id++,
                                 NULL, 0);
    }

    if (ctx->conn) {
        ngx_http_xngin_stream_del(ctx->conn, ctx->stream_id);
    }

    ctx->state = XNAP_ST_ABORTED;
    ctx->conn = NULL;
}


/* ---------- timeout / failure ---------- */

void
ngx_http_xngin_timeout(ngx_event_t *ev)
{
    ngx_http_xngin_ctx_t   *ctx = ev->data;
    ngx_http_request_t     *r = ctx->r;

    ctx->state = XNAP_ST_TIMEDOUT;
    ngx_str_set(&ctx->error, "timeout");

    if (ctx->conn) {
        ngx_http_xngin_conn_send(ctx->conn, XNAP_FRAME_ABORT, 0,
                                 ctx->stream_id, ctx->frame_id++, NULL, 0);
        ngx_http_xngin_stream_del(ctx->conn, ctx->stream_id);
        ctx->conn = NULL;
    }

    if (ctx->body_stream && !ctx->body_read) {
        /* upload still in flight — can't replay the stream on a fresh
           conn; drain the body, body_post resolves the request */
        ctx->body_stream = 0;
        ctx->stream_failed = 1;
        return;
    }

    if (!ctx->retried) {
        ctx->retried = 1;
        if (ngx_http_xngin_dispatch(r, ctx) == NGX_OK) {
            if (!ctx->async) {
                ngx_http_xngin_loc_conf_t *lcf;
                lcf = ngx_http_get_module_loc_conf(r,
                                                   ngx_http_xngin_module);
                ngx_add_timer(ctx->timer, lcf->timeout);
            }
            return;
        }
    }

    ngx_http_xngin_fail(ctx, "timeout");
}


void
ngx_http_xngin_ctx_conn_failed(ngx_http_xngin_ctx_t *ctx)
{
    ngx_http_request_t *r = ctx->r;

    ctx->conn = NULL;

    if (ctx->is_resp) {
        ngx_http_xngin_resp_conn_failed(ctx);
        return;
    }

    if (ctx->state != XNAP_ST_SENT) {
        return;
    }

    if (ctx->async) {
        ctx->state = XNAP_ST_ABORTED;
        return;   /* nothing to resume; request already proceeded */
    }

    if (ctx->body_stream && !ctx->body_read) {
        /* mid-upload: the body can't be replayed on another conn.
           Defer to body_post — same place a slow upload already waits. */
        ctx->body_stream = 0;
        ctx->stream_failed = 1;
        return;
    }

    if (!ctx->retried) {
        ctx->retried = 1;
        if (ngx_http_xngin_dispatch(r, ctx) == NGX_OK) {
            return;   /* timer still armed from original dispatch */
        }
    }

    ngx_str_set(&ctx->error, "down");
    ngx_http_xngin_fail(ctx, "down");
}


static void
ngx_http_xngin_fail(ngx_http_xngin_ctx_t *ctx, const char *err)
{
    ngx_http_xngin_loc_conf_t *lcf;
    ngx_http_request_t        *r = ctx->r;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xngin_module);

    ctx->state = XNAP_ST_DONE;

    if (ctx->async) {
        return;
    }

    if (lcf->fail == XNAP_FAIL_OPEN) {
        ngx_http_xngin_resume(r, NGX_DECLINED);
    } else {
        ngx_http_xngin_resume(r, NGX_HTTP_SERVICE_UNAVAILABLE);
    }
}


/* ---------- deny content handler (custom body) ---------- */

static ngx_int_t
ngx_http_xngin_deny_content(ngx_http_request_t *r)
{
    ngx_http_xngin_ctx_t *ctx;
    ngx_buf_t            *b;
    ngx_chain_t           out;
    ngx_int_t             rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xngin_module);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = ctx->deny_status;
    r->headers_out.content_length_n = ctx->deny_body.len;

    if (ctx->deny_ctype.len) {
        r->headers_out.content_type = ctx->deny_ctype;
        r->headers_out.content_type_len = ctx->deny_ctype.len;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos = ctx->deny_body.data;
    b->last = ctx->deny_body.data + ctx->deny_body.len;
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


/* ---------- verdict ---------- */

void
ngx_http_xngin_parse_vars(ngx_http_request_t *r, ngx_http_xngin_ctx_t *ctx,
    u_char *data, size_t len)
{
    ngx_xnap_rbuf_t        rb;
    ngx_str_t              name;
    ngx_xnap_val_t         v;
    ngx_http_xngin_var_t  *kv;

    rb.pos = data;
    rb.end = data + len;
    rb.err = 0;

    while (ngx_xnap_rbuf_kv(&rb, &name, &v) == NGX_OK) {
        if (v.type != XNAP_VT_STR) {
            continue;
        }

        if (ctx->vars == NULL) {
            ctx->vars = ngx_array_create(r->pool, 4,
                                         sizeof(ngx_http_xngin_var_t));
            if (ctx->vars == NULL) {
                return;
            }
        }

        kv = ngx_array_push(ctx->vars);
        if (kv == NULL) {
            return;
        }

        kv->name.len = name.len;
        kv->name.data = ngx_pnalloc(r->pool, name.len);
        ngx_memcpy(kv->name.data, name.data, name.len);
        kv->value.len = v.s.len;
        kv->value.data = ngx_pnalloc(r->pool, v.s.len);
        ngx_memcpy(kv->value.data, v.s.data, v.s.len);
    }
}


static void
ngx_http_xngin_parse_hdr_set(ngx_http_request_t *r,
    u_char *data, size_t len)
{
    ngx_xnap_rbuf_t rb;
    ngx_str_t       name;
    ngx_xnap_val_t  v;

    rb.pos = data;
    rb.end = data + len;
    rb.err = 0;

    while (ngx_xnap_rbuf_kv(&rb, &name, &v) == NGX_OK) {
        if (v.type != XNAP_VT_STR) {
            continue;
        }
        ngx_http_xngin_hdr_set(r, &name, &v.s);
    }
}


static void
ngx_http_xngin_parse_hdr_unset(ngx_http_request_t *r,
    u_char *data, size_t len, uint64_t count)
{
    ngx_xnap_rbuf_t rb;
    ngx_str_t       s;
    uint64_t        i;

    rb.pos = data;
    rb.end = data + len;
    rb.err = 0;

    for (i = 0; i < count; i++) {
        if (ngx_xnap_rbuf_strlist_next(&rb, &s) != NGX_OK) {
            return;
        }
        ngx_http_xngin_hdr_unset(r, &s);
    }
}


static ngx_int_t
ngx_http_xngin_hdr_set(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    ngx_list_part_t   *part;
    ngx_table_elt_t   *h, *new;
    ngx_uint_t         i;
    u_char            *low;

    low = ngx_pnalloc(r->pool, name->len);
    if (low == NULL) {
        return NGX_ERROR;
    }

    /* find existing header by lowercased name */
    part = &r->headers_in.headers.part;
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
            ngx_memcpy(h[i].value.data, value->data, value->len);
            h[i].value.len = value->len;
            h[i].hash = 1;
            return NGX_OK;
        }
    }

    new = ngx_list_push(&r->headers_in.headers);
    if (new == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(low, name->data, name->len);
    new->hash = 1;
    new->key.len = name->len;
    new->key.data = ngx_pnalloc(r->pool, name->len);
    ngx_memcpy(new->key.data, name->data, name->len);
    new->value.len = value->len;
    new->value.data = ngx_pnalloc(r->pool, value->len);
    ngx_memcpy(new->value.data, value->data, value->len);
    new->lowcase_key = low;

    return NGX_OK;
}


static void
ngx_http_xngin_hdr_unset(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_list_part_t   *part;
    ngx_table_elt_t   *h;
    ngx_uint_t         i;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                return;
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
}


void
ngx_http_xngin_parse_res_hdr_set(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx, u_char *data, size_t len)
{
    ngx_xnap_rbuf_t        rb;
    ngx_str_t              name;
    ngx_xnap_val_t         v;
    ngx_http_xngin_var_t  *kv;

    rb.pos = data;
    rb.end = data + len;
    rb.err = 0;

    while (ngx_xnap_rbuf_kv(&rb, &name, &v) == NGX_OK) {
        if (v.type != XNAP_VT_STR) {
            continue;
        }

        if (ctx->res_hdr_set == NULL) {
            ctx->res_hdr_set = ngx_array_create(r->pool, 4,
                                              sizeof(ngx_http_xngin_var_t));
            if (ctx->res_hdr_set == NULL) {
                return;
            }
        }

        kv = ngx_array_push(ctx->res_hdr_set);
        if (kv == NULL) {
            return;
        }

        kv->name.len = name.len;
        kv->name.data = ngx_pnalloc(r->pool, name.len);
        ngx_memcpy(kv->name.data, name.data, name.len);
        kv->value.len = v.s.len;
        kv->value.data = ngx_pnalloc(r->pool, v.s.len);
        ngx_memcpy(kv->value.data, v.s.data, v.s.len);
    }
}


void
ngx_http_xngin_parse_res_hdr_unset(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx, u_char *data, size_t len, uint64_t count)
{
    ngx_xnap_rbuf_t  rb;
    ngx_str_t        s, *name;
    uint64_t         i;

    rb.pos = data;
    rb.end = data + len;
    rb.err = 0;

    for (i = 0; i < count; i++) {
        if (ngx_xnap_rbuf_strlist_next(&rb, &s) != NGX_OK) {
            return;
        }

        if (ctx->res_hdr_unset == NULL) {
            ctx->res_hdr_unset = ngx_array_create(r->pool, 4,
                                                sizeof(ngx_str_t));
            if (ctx->res_hdr_unset == NULL) {
                return;
            }
        }

        name = ngx_array_push(ctx->res_hdr_unset);
        if (name == NULL) {
            return;
        }

        name->len = s.len;
        name->data = ngx_pnalloc(r->pool, s.len);
        ngx_memcpy(name->data, s.data, s.len);
    }
}


void
ngx_http_xngin_apply_req_body(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx)
{
    ngx_http_request_body_t *rb = r->request_body;
    ngx_chain_t             *cl;
    ngx_buf_t               *b;
    ngx_str_t                cl_val, name;

    if (rb == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xngin: req-body ignored, request body not captured");
        return;
    }

    b = ngx_calloc_buf(r->pool);
    cl = ngx_alloc_chain_link(r->pool);
    if (b == NULL || cl == NULL) {
        return;
    }

    b->pos = ctx->req_body.data;
    b->last = ctx->req_body.data + ctx->req_body.len;
    b->memory = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;

    cl->buf = b;
    cl->next = NULL;

    rb->bufs = cl;
    rb->buf = NULL;

    /* rewrite framing headers to match the new body */
    ngx_str_set(&name, "transfer-encoding");
    ngx_http_xngin_hdr_unset(r, &name);
    r->headers_in.chunked = 0;

    ngx_str_set(&name, "content-length");

    if (ctx->req_body.len == 0) {
        ngx_http_xngin_hdr_unset(r, &name);
        r->headers_in.content_length_n = -1;
        return;
    }

    cl_val.data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
    if (cl_val.data == NULL) {
        return;
    }
    cl_val.len = ngx_snprintf(cl_val.data, NGX_OFF_T_LEN, "%O",
                             (off_t) ctx->req_body.len) - cl_val.data;

    if (ngx_http_xngin_hdr_set(r, &name, &cl_val) == NGX_OK
        && r->headers_in.content_length)
    {
        r->headers_in.content_length->value = cl_val;
    }
    r->headers_in.content_length_n = (off_t) ctx->req_body.len;
}


ngx_int_t
ngx_http_xngin_verdict(ngx_http_xngin_conn_t *c, ngx_http_xngin_ctx_t *ctx,
    u_char *payload, size_t len)
{
    ngx_http_request_t     *r = ctx->r;
    ngx_xnap_rbuf_t         rb;
    ngx_str_t               name;
    ngx_xnap_val_t          v;
    ngx_str_t               action = ngx_null_string;
    ngx_int_t               status = 0;
    ngx_str_t               location = ngx_null_string;
    uint64_t                cache_ttl = 0;
    unsigned                mutable = 0;   /* verdict has side effects */
    ngx_int_t               rc;

    if (ctx->state != XNAP_ST_SENT) {
        return NGX_OK;
    }

    ctx->agent_rtt = ngx_http_xngin_now_us() - ctx->sent_at;

    ngx_http_xngin_stream_del(c, ctx->stream_id);
    ctx->conn = NULL;
    ctx->state = XNAP_ST_DONE;

    if (ctx->timer && ctx->timer->timer_set) {
        ngx_del_timer(ctx->timer);
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
            ctx->deny_body.data = ngx_pnalloc(r->pool, v.s.len);
            ngx_memcpy(ctx->deny_body.data, v.s.data, v.s.len);
            ctx->deny_body.len = v.s.len;
            mutable = 1;
        }
        else if (name.len == 12
                 && ngx_memcmp(name.data, "content-type", 12) == 0)
        {
            ctx->deny_ctype.data = ngx_pnalloc(r->pool, v.s.len);
            ngx_memcpy(ctx->deny_ctype.data, v.s.data, v.s.len);
            ctx->deny_ctype.len = v.s.len;
        }
        else if (name.len == 8
                 && ngx_memcmp(name.data, "location", 8) == 0)
        {
            location.data = ngx_pnalloc(r->pool, v.s.len);
            ngx_memcpy(location.data, v.s.data, v.s.len);
            location.len = v.s.len;
            mutable = 1;
        }
        else if (name.len == 7
                 && ngx_memcmp(name.data, "hdr-set", 7) == 0)
        {
            ngx_http_xngin_parse_hdr_set(r, v.sub, v.sub_len);
            mutable = 1;
        }
        else if (name.len == 9
                 && ngx_memcmp(name.data, "hdr-unset", 9) == 0)
        {
            ngx_http_xngin_parse_hdr_unset(r, v.sub, v.sub_len, v.u);
            mutable = 1;
        }
        else if (name.len == 8
                 && ngx_memcmp(name.data, "req-body", 8) == 0)
        {
            ctx->req_body.data = ngx_pnalloc(r->pool, v.s.len);
            ngx_memcpy(ctx->req_body.data, v.s.data, v.s.len);
            ctx->req_body.len = v.s.len;
            ctx->req_body_set = 1;
            mutable = 1;
        }
        else if (name.len == 11
                 && ngx_memcmp(name.data, "res-hdr-set", 11) == 0)
        {
            ngx_http_xngin_parse_res_hdr_set(r, ctx, v.sub, v.sub_len);
            mutable = 1;
        }
        else if (name.len == 13
                 && ngx_memcmp(name.data, "res-hdr-unset", 13) == 0)
        {
            ngx_http_xngin_parse_res_hdr_unset(r, ctx, v.sub, v.sub_len, v.u);
            mutable = 1;
        }
        else if (name.len == 8
                 && ngx_memcmp(name.data, "res-body", 8) == 0)
        {
            ctx->res_body.data = ngx_pnalloc(r->pool, v.s.len);
            ngx_memcpy(ctx->res_body.data, v.s.data, v.s.len);
            ctx->res_body.len = v.s.len;
            ctx->res_body_set = 1;
            mutable = 1;
        }
        else if (name.len == 4 && ngx_memcmp(name.data, "vars", 4) == 0) {
            ngx_http_xngin_parse_vars(r, ctx, v.sub, v.sub_len);
            mutable = 1;   /* vars would be lost on a cache hit */
        }
        else if (name.len == 9
                 && ngx_memcmp(name.data, "cache-ttl", 9) == 0)
        {
            cache_ttl = v.u;
        }
        else if (name.len == 9
                 && ngx_memcmp(name.data, "cache-key", 9) == 0)
        {
            /* accepted for forward-compat; engine key is authoritative */
        }
        else if (name.len == 6 && ngx_memcmp(name.data, "reason", 6) == 0) {
            ctx->reason.data = ngx_pnalloc(r->pool, v.s.len);
            ngx_memcpy(ctx->reason.data, v.s.data, v.s.len);
            ctx->reason.len = v.s.len;
        }
        else if (name.len == 5 && ngx_memcmp(name.data, "score", 5) == 0) {
            ctx->score = v.i;
        }
    }

    ctx->action = action;

    if (ctx->async) {
        /* request already proceeded; store outcome for logging only */
        return NGX_OK;
    }

    /* apply */
    if (action.len == 5 && ngx_memcmp(action.data, "allow", 5) == 0) {
        if (ctx->req_body_set && ctx->body_read) {
            /* mid-upload early verdict: body_post applies once the
               read machinery has finished with rb->bufs */
            ngx_http_xngin_apply_req_body(r, ctx);
        }
        if (ctx->cache_key_val.len && cache_ttl && !mutable) {
            ngx_http_xngin_cache_store(r, ctx, &ctx->cache_key_val,
                                       (uint32_t) cache_ttl);
        }
        ngx_http_xngin_resume(r, NGX_DECLINED);
        return NGX_OK;
    }

    if (action.len == 4 && ngx_memcmp(action.data, "deny", 4) == 0) {
        ctx->deny_status = (status >= 400 && status < 600)
                           ? status : NGX_HTTP_FORBIDDEN;

        if (ctx->cache_key_val.len && cache_ttl && !mutable) {
            ngx_http_xngin_cache_store(r, ctx, &ctx->cache_key_val,
                                       (uint32_t) cache_ttl);
        }

        if (ctx->deny_body.len) {
            /* proceed to content phase; our content handler emits body */
            r->content_handler = ngx_http_xngin_deny_content;
            ngx_http_xngin_resume(r, NGX_DECLINED);
        } else {
            ngx_http_xngin_resume(r, ctx->deny_status);
        }
        return NGX_OK;
    }

    if (action.len == 8 && ngx_memcmp(action.data, "redirect", 8) == 0) {
        ngx_table_elt_t  *loch;

        loch = ngx_list_push(&r->headers_out.headers);
        if (loch == NULL) {
            ngx_http_xngin_resume(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        loch->hash = 1;
        ngx_str_set(&loch->key, "Location");
        loch->value = location;
        r->headers_out.location = loch;

        if (status != NGX_HTTP_MOVED_PERMANENTLY
            && status != NGX_HTTP_MOVED_TEMPORARILY
            && status != NGX_HTTP_SEE_OTHER
            && status != NGX_HTTP_TEMPORARY_REDIRECT)
        {
            status = NGX_HTTP_MOVED_TEMPORARILY;
        }

        ngx_http_xngin_resume(r, status);
        return NGX_OK;
    }

    /* missing/unknown action: deny 500 (spec fail-closed) */
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "xngin: malformed verdict action \"%V\"", &action);
    ngx_http_xngin_resume(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return NGX_OK;
}
