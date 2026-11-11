#include "ngx_http_xngin_module.h"


#define XNAP_SID_TOMBSTONE  ((uint64_t) -1)
#define XNAP_RBUF_MAX       (1024 * 1024)


static void ngx_http_xngin_conn_read(ngx_event_t *ev);
static void ngx_http_xngin_conn_write(ngx_event_t *ev);
static void ngx_http_xngin_conn_timer(ngx_event_t *ev);
static void ngx_http_xngin_conn_close(ngx_http_xngin_conn_t *c);
static void ngx_http_xngin_conn_connect(ngx_http_xngin_conn_t *c);
static void ngx_http_xngin_conn_fail_streams(ngx_http_xngin_conn_t *c);
static ngx_int_t ngx_http_xngin_conn_flush(ngx_http_xngin_conn_t *c);

void ngx_http_xngin_ctx_conn_failed(ngx_http_xngin_ctx_t *ctx);


/* ---------- raw stack encoders (handshake path) ---------- */

static u_char *
xnap_enc_varint(u_char *p, uint64_t v)
{
    while (v >= 0x80) {
        *p++ = (u_char) (v | 0x80);
        v >>= 7;
    }
    *p++ = (u_char) v;
    return p;
}


static u_char *
xnap_enc_kv_name(u_char *p, const char *name, size_t len)
{
    p = xnap_enc_varint(p, len);
    p = ngx_cpymem(p, name, len);
    return p;
}


static u_char *
xnap_enc_kv_uint(u_char *p, const char *name, uint64_t v)
{
    p = xnap_enc_kv_name(p, name, ngx_strlen(name));
    *p++ = XNAP_VT_UINT64;
    return xnap_enc_varint(p, v);
}


static u_char *
xnap_enc_kv_str(u_char *p, const char *name, u_char *val, size_t len)
{
    p = xnap_enc_kv_name(p, name, ngx_strlen(name));
    *p++ = XNAP_VT_STR;
    p = xnap_enc_varint(p, len);
    return ngx_cpymem(p, val, len);
}


/* ---------- stream table (open addressing + tombstones) ---------- */

void
ngx_http_xngin_stream_add(ngx_http_xngin_conn_t *c, uint64_t sid,
    ngx_http_xngin_ctx_t *ctx)
{
    ngx_uint_t          i;
    ngx_xnap_stream_t  *st, *first = NULL;

    for (i = 0; i < c->streams_cap; i++) {
        st = &c->streams[(sid + i) % c->streams_cap];

        if (st->id == 0 || st->id == XNAP_SID_TOMBSTONE) {
            if (first == NULL) {
                first = st;
            }
            if (st->id == 0) {
                break;
            }
        }
    }

    if (first) {
        first->id = sid;
        first->ctx = ctx;
        c->nstreams++;
    }
}


ngx_http_xngin_ctx_t *
ngx_http_xngin_stream_find(ngx_http_xngin_conn_t *c, uint64_t sid)
{
    ngx_uint_t          i;
    ngx_xnap_stream_t  *st;

    for (i = 0; i < c->streams_cap; i++) {
        st = &c->streams[(sid + i) % c->streams_cap];

        if (st->id == 0) {
            return NULL;
        }

        if (st->id == sid) {
            return st->ctx;
        }
    }

    return NULL;
}


void
ngx_http_xngin_stream_del(ngx_http_xngin_conn_t *c, uint64_t sid)
{
    ngx_uint_t          i;
    ngx_xnap_stream_t  *st;

    if (c->streams == NULL) {
        return;
    }

    for (i = 0; i < c->streams_cap; i++) {
        st = &c->streams[(sid + i) % c->streams_cap];

        if (st->id == 0) {
            return;
        }

        if (st->id == sid) {
            st->id = XNAP_SID_TOMBSTONE;
            st->ctx = NULL;
            if (c->nstreams) {
                c->nstreams--;
            }
            return;
        }
    }
}


/* ---------- worker lifecycle ---------- */

ngx_int_t
ngx_http_xngin_conn_init_worker(ngx_http_xngin_main_conf_t *mmcf,
    ngx_cycle_t *cycle)
{
    ngx_uint_t               i, j, k;
    ngx_http_xngin_group_t  *g;
    ngx_http_xngin_agent_t  *a;
    ngx_http_xngin_conn_t   *c;

    if (mmcf->groups == NULL) {
        return NGX_OK;
    }

    g = mmcf->groups->elts;

    for (i = 0; i < mmcf->groups->nelts; i++) {
        a = g[i].agents.elts;

        for (j = 0; j < g[i].agents.nelts; j++) {
            for (k = 0; k < g[i].keepalive * a[j].weight; k++) {

                c = ngx_pcalloc(cycle->pool,
                                sizeof(ngx_http_xngin_conn_t));
                if (c == NULL) {
                    return NGX_ERROR;
                }

                c->agent = &a[j];
                c->out_tail = &c->out;
                c->streams_cap = XNAP_STREAM_TABLE_CAP;
                c->streams = ngx_pcalloc(cycle->pool,
                            c->streams_cap * sizeof(ngx_xnap_stream_t));
                c->rbuf = ngx_alloc(XNAP_RBUF_SIZE, cycle->log);
                c->rpos = c->rlast = c->rbuf;
                c->next_sid = 1;
                c->max_streams = a[j].max_streams
                                 ? a[j].max_streams
                                 : XNAP_DEFAULT_MAX_STREAM;
                c->max_frame = XNAP_DEFAULT_MAX_FRAME;
                c->down = 1;

                c->timer = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
                c->timer->handler = ngx_http_xngin_conn_timer;
                c->timer->data = c;
                c->timer->log = cycle->log;

                c->next = a[j].conns;
                a[j].conns = c;

                ngx_http_xngin_conn_connect(c);
            }
        }
    }

    return NGX_OK;
}


void
ngx_http_xngin_conn_free_worker(ngx_http_xngin_main_conf_t *mmcf,
    ngx_cycle_t *cycle)
{
    /* worker exit: OS reclaims sockets and the cycle pool */
    return;
}


static void
ngx_http_xngin_conn_connect(ngx_http_xngin_conn_t *c)
{
    ngx_int_t            rc;
    ngx_peer_connection_t *pc;
    ngx_addr_t           *addr = &c->agent->addr;

    c->down = 0;   /* attempting connect */

    pc = &c->pc;
    ngx_memzero(pc, sizeof(ngx_peer_connection_t));

    pc->sockaddr = addr->sockaddr;
    pc->socklen = addr->socklen;
    pc->name = &c->agent->url_text;
    pc->get = ngx_event_get_peer;
    pc->log = ngx_cycle->log;
    pc->log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(pc);

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                      "xngin: connect to agent %V failed", &c->agent->url_text);
        c->down = 1;
        ngx_add_timer(c->timer, XNAP_RECONNECT_DELAY);
        return;
    }

    /* rc == NGX_OK or NGX_AGAIN */
    pc->connection->data = c;
    pc->connection->read->handler = ngx_http_xngin_conn_read;
    pc->connection->write->handler = ngx_http_xngin_conn_write;

    if (rc == NGX_OK) {
        ngx_http_xngin_conn_write(pc->connection->write);
    }
}


/* ---------- send ---------- */

ngx_int_t
ngx_http_xngin_conn_send(ngx_http_xngin_conn_t *c, u_char type,
    uint32_t flags, uint64_t sid, uint64_t fid, u_char *payload, size_t len)
{
    ngx_xnap_pkt_t *pkt;
    size_t          flen, hlen;
    u_char         *p;

    if (c->down || c->pc.connection == NULL) {
        return NGX_ERROR;
    }

    flen = 1 + 4 + ngx_xnap_varint_len(sid) + ngx_xnap_varint_len(fid) + len;
    hlen = ngx_xnap_varint_len(flen);

    pkt = ngx_alloc(sizeof(ngx_xnap_pkt_t) + hlen + flen, ngx_cycle->log);
    if (pkt == NULL) {
        return NGX_ERROR;
    }

    p = pkt->data;
    p = xnap_enc_varint(p, flen);
    *p++ = type;
    *p++ = (u_char) (flags >> 24);
    *p++ = (u_char) (flags >> 16);
    *p++ = (u_char) (flags >> 8);
    *p++ = (u_char) flags;
    p = xnap_enc_varint(p, sid);
    p = xnap_enc_varint(p, fid);

    if (len) {
        p = ngx_cpymem(p, payload, len);
    }

    pkt->pos = pkt->data;
    pkt->last = p;
    pkt->next = NULL;

    *c->out_tail = pkt;
    c->out_tail = &pkt->next;

    ngx_http_xngin_conn_write(c->pc.connection->write);

    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_conn_flush(ngx_http_xngin_conn_t *c)
{
    ssize_t           n;
    ngx_xnap_pkt_t   *pkt;
    ngx_connection_t *nc = c->pc.connection;

    while (c->out) {
        pkt = c->out;

        n = nc->send(nc, pkt->pos, pkt->last - pkt->pos);

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        pkt->pos += n;

        if (pkt->pos < pkt->last) {
            return NGX_AGAIN;
        }

        c->out = pkt->next;
        if (c->out == NULL) {
            c->out_tail = &c->out;
        }
        ngx_free(pkt);
    }

    return NGX_OK;
}


static void
ngx_http_xngin_conn_write(ngx_event_t *ev)
{
    ngx_connection_t      *nc = ev->data;
    ngx_http_xngin_conn_t *c = nc->data;

    if (c->down) {
        return;
    }

    if (!c->hello_sent) {
        u_char     payload[256], eid[64], *p;
        ngx_str_t  e;

        e.len = ngx_snprintf(eid, sizeof(eid), "nginx/%d.%d.%d w%P",
                             nginx_version / 1000000,
                             (nginx_version / 1000) % 1000,
                             nginx_version % 1000,
                             ngx_pid) - eid;
        e.data = eid;

        p = payload;
        p = xnap_enc_kv_uint(p, "version", XNAP_VERSION);
        p = xnap_enc_kv_uint(p, "max-frame-size", XNAP_DEFAULT_MAX_FRAME);
        p = xnap_enc_kv_uint(p, "max-streams", XNAP_DEFAULT_MAX_STREAM);
        p = xnap_enc_kv_uint(p, "capabilities",
                             XNAP_CAP_BODY | XNAP_CAP_ASYNC | XNAP_CAP_VCACHE
                             | XNAP_CAP_RESP);
        p = xnap_enc_kv_str(p, "engine-id", e.data, e.len);

        c->hello_sent = 1;

        if (ngx_http_xngin_conn_send(c, XNAP_FRAME_ENGINE_HELLO, 0, 0, 0,
                                   payload, p - payload)
            != NGX_OK)
        {
            ngx_http_xngin_conn_close(c);
            return;
        }
        /* conn_send flushed already; just ensure watch */
    } else {
        if (ngx_http_xngin_conn_flush(c) == NGX_ERROR) {
            ngx_http_xngin_conn_close(c);
            return;
        }
    }

    if (nc->write->ready == 0
        && ngx_handle_write_event(nc->write, 0) != NGX_OK)
    {
        ngx_http_xngin_conn_close(c);
    }
}


/* ---------- recv / frame dispatch ---------- */

static ngx_int_t
ngx_http_xngin_conn_frame(ngx_http_xngin_conn_t *c, u_char type,
    uint32_t flags, uint64_t sid, uint64_t fid,
    u_char *payload, size_t len)
{
    ngx_http_xngin_ctx_t  *ctx;
    ngx_xnap_rbuf_t        rb;
    ngx_str_t              name;
    ngx_xnap_val_t         v;
    uint64_t               ver = 0;

    switch (type) {

    case XNAP_FRAME_AGENT_HELLO:
        rb.pos = payload;
        rb.end = payload + len;
        rb.err = 0;

        while (ngx_xnap_rbuf_kv(&rb, &name, &v) == NGX_OK) {
            if (name.len == 7 && ngx_memcmp(name.data, "version", 7) == 0) {
                ver = v.u;
            } else if (name.len == 11
                       && ngx_memcmp(name.data, "max-streams", 11) == 0)
            {
                if (v.u && v.u < c->max_streams) {
                    c->max_streams = (ngx_uint_t) v.u;
                }
            } else if (name.len == 14
                       && ngx_memcmp(name.data, "max-frame-size", 14) == 0)
            {
                if (v.u && v.u < c->max_frame) {
                    c->max_frame = (size_t) v.u;
                }
            } else if (name.len == 12
                       && ngx_memcmp(name.data, "capabilities", 12) == 0)
            {
                c->agent_caps = (uint32_t) v.u;
            }
        }

        if (rb.err || ver != XNAP_VERSION) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "xngin: agent %V protocol version mismatch",
                          &c->agent->url_text);
            return NGX_ERROR;
        }

        c->ready = 1;
        c->down = 0;
        c->missed_pongs = 0;
        ngx_add_timer(c->timer, c->agent->group->ping_interval);

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "xngin: agent %V ready (max_streams=%ui)",
                      &c->agent->url_text, c->max_streams);
        return NGX_OK;

    case XNAP_FRAME_VERDICT:
        ctx = ngx_http_xngin_stream_find(c, sid);
        if (ctx == NULL) {
            return NGX_OK;  /* late verdict for aborted stream */
        }
        if (ctx->is_resp) {
            return ngx_http_xngin_resp_verdict(c, ctx, payload, len);
        }
        return ngx_http_xngin_verdict(c, ctx, payload, len);

    case XNAP_FRAME_PING:
        return ngx_http_xngin_conn_send(c, XNAP_FRAME_PONG, 0, 0, fid,
                                      payload, len);

    case XNAP_FRAME_PONG:
        c->missed_pongs = 0;
        c->last_rtt = ngx_current_msec - c->ping_sent_at;
        return NGX_OK;

    case XNAP_FRAME_ABORT:
        ctx = ngx_http_xngin_stream_find(c, sid);
        if (ctx) {
            ngx_http_xngin_stream_del(c, sid);
            ngx_http_xngin_ctx_conn_failed(ctx);
        }
        return NGX_OK;

    case XNAP_FRAME_DISCON:
        return NGX_ERROR;

    default:
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "xngin: unknown frame type %d from %V",
                      type, &c->agent->url_text);
        return NGX_OK;
    }

    /* unreachable */
    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_conn_parse(ngx_http_xngin_conn_t *c)
{
    u_char    *p, *frame;
    uint64_t   flen, sid, fid;
    u_char     type;
    uint32_t   flags;
    unsigned   shift;
    ngx_int_t  rc;

    for (;;) {

        /* peek frame-len varint */
        flen = 0;
        shift = 0;
        frame = NULL;
        {
            u_char   *q = c->rpos;
            unsigned  done = 0;

            while (q < c->rlast && shift < 70) {
                u_char b = *q++;
                flen |= (uint64_t) (b & 0x7f) << shift;
                shift += 7;
                if (!(b & 0x80)) {
                    done = 1;
                    break;
                }
            }

            if (!done) {
                if (q - c->rpos >= 10) {
                    return NGX_ERROR;   /* overlong varint */
                }
                return NGX_AGAIN;       /* need more bytes */
            }
            frame = q;
        }

        if (flen < 6 || flen > c->max_frame) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "xngin: bad frame len %uL from %V",
                          flen, &c->agent->url_text);
            return NGX_ERROR;
        }

        if ((uint64_t) (c->rlast - frame) < flen) {
            return NGX_AGAIN;
        }

        /* frame = type(1) + flags(4) + sid varint + fid varint + payload */
        p = frame;

        type = *p++;
        flags = ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
                | ((uint32_t) p[2] << 8) | p[3];
        p += 4;

        sid = 0;
        shift = 0;
        for (;;) {
            u_char b = *p++;
            sid |= (uint64_t) (b & 0x7f) << shift;
            shift += 7;
            if (!(b & 0x80)) {
                break;
            }
        }

        fid = 0;
        shift = 0;
        for (;;) {
            u_char b = *p++;
            fid |= (uint64_t) (b & 0x7f) << shift;
            shift += 7;
            if (!(b & 0x80)) {
                break;
            }
        }

        c->rpos = frame + flen;

        rc = ngx_http_xngin_conn_frame(c, type, flags, sid, fid,
                                       p, flen - (p - frame));
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }
    }
}


static void
ngx_http_xngin_conn_read(ngx_event_t *ev)
{
    ngx_connection_t      *nc = ev->data;
    ngx_http_xngin_conn_t *c = nc->data;
    ssize_t                n;
    ngx_int_t              rc;
    size_t                 used, space;

    if (c->down) {
        return;
    }

    for (;;) {
        /* compact read buffer */
        if (c->rpos > c->rbuf) {
            used = c->rlast - c->rpos;
            ngx_memmove(c->rbuf, c->rpos, used);
            c->rpos = c->rbuf;
            c->rlast = c->rbuf + used;
        }

        space = XNAP_RBUF_SIZE - (c->rlast - c->rbuf);
        if (space == 0) {
            ngx_log_error(NGX_LOG_ERR, nc->log, 0,
                          "xngin: read buffer overflow from %V",
                          &c->agent->url_text);
            ngx_http_xngin_conn_close(c);
            return;
        }

        n = nc->recv(nc, c->rlast, space);

        if (n > 0) {
            c->rlast += n;

            rc = ngx_http_xngin_conn_parse(c);
            if (rc == NGX_ERROR) {
                ngx_http_xngin_conn_close(c);
                return;
            }
            continue;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        /* n == 0 or NGX_ERROR: agent closed / error */
        ngx_http_xngin_conn_close(c);
        return;
    }

    if (ngx_handle_read_event(nc->read, 0) != NGX_OK) {
        ngx_http_xngin_conn_close(c);
    }
}


/* ---------- failure / reconnect ---------- */

static void
ngx_http_xngin_conn_close(ngx_http_xngin_conn_t *c)
{
    ngx_xnap_pkt_t *pkt, *next;

    if (c->down) {
        return;
    }

    c->down = 1;
    c->ready = 0;
    c->hello_sent = 0;
    c->missed_pongs = 0;

    if (c->pc.connection) {
        ngx_close_connection(c->pc.connection);
        c->pc.connection = NULL;
    }

    for (pkt = c->out; pkt; pkt = next) {
        next = pkt->next;
        ngx_free(pkt);
    }
    c->out = NULL;
    c->out_tail = &c->out;

    c->rpos = c->rlast = c->rbuf;

    /* fail in-flight streams, then wipe the table */
    ngx_http_xngin_conn_fail_streams(c);

    if (!c->timer->timedout) {
        ngx_del_timer(c->timer);
    }
    ngx_add_timer(c->timer, XNAP_RECONNECT_DELAY);
}


static void
ngx_http_xngin_conn_fail_streams(ngx_http_xngin_conn_t *c)
{
    ngx_uint_t           i;
    ngx_http_xngin_ctx_t *ctx;

    for (i = 0; i < c->streams_cap; i++) {
        if (c->streams[i].id && c->streams[i].id != XNAP_SID_TOMBSTONE) {
            ctx = c->streams[i].ctx;
            c->streams[i].id = 0;
            c->streams[i].ctx = NULL;
            c->nstreams = 0;

            if (ctx) {
                ngx_http_xngin_ctx_conn_failed(ctx);
            }
        }
    }
    c->nstreams = 0;
}


static void
ngx_http_xngin_conn_timer(ngx_event_t *ev)
{
    ngx_http_xngin_conn_t *c = ev->data;
    u_char                 payload[8], *p;

    if (ngx_quit || ngx_exiting) {
        return;
    }

    if (c->down) {
        /* reconnect attempt */
        c->down = 0;
        ngx_http_xngin_conn_connect(c);
        return;
    }

    if (c->missed_pongs >= XNAP_MAX_PONG_MISSES) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "xngin: agent %V missed pongs, closing",
                      &c->agent->url_text);
        ngx_http_xngin_conn_close(c);
        return;
    }

    p = xnap_enc_kv_name(payload, "data", 4);
    /* echo 4-byte timestamp-ish data */
    *p++ = XNAP_VT_BIN;
    *p++ = 1;
    *p++ = (u_char) (ngx_current_msec & 0xff);

    c->ping_sent_at = ngx_current_msec;
    c->missed_pongs++;

    if (ngx_http_xngin_conn_send(c, XNAP_FRAME_PING, 0, 0, 0,
                               payload, p - payload)
        != NGX_OK)
    {
        ngx_http_xngin_conn_close(c);
        return;
    }

    ngx_add_timer(c->timer, c->agent->group->ping_interval);
}


/* ---------- pick a connection ---------- */

ngx_http_xngin_conn_t *
ngx_http_xngin_conn_pick_caps(ngx_http_xngin_group_t *g, uint32_t caps)
{
    ngx_uint_t              i;
    ngx_http_xngin_agent_t *a = g->agents.elts;
    ngx_http_xngin_conn_t  *c, *best = NULL;

    for (i = 0; i < g->agents.nelts; i++) {
        for (c = a[i].conns; c; c = c->next) {
            if (!c->ready || c->down) {
                continue;
            }
            if (c->nstreams >= c->max_streams) {
                continue;
            }
            if ((c->agent_caps & caps) != caps) {
                continue;
            }
            if (best == NULL
                || (double) c->nstreams / c->max_streams
                   < (double) best->nstreams / best->max_streams)
            {
                best = c;
            }
        }
    }

    return best;
}


ngx_http_xngin_conn_t *
ngx_http_xngin_conn_pick(ngx_http_xngin_group_t *g)
{
    return ngx_http_xngin_conn_pick_caps(g, 0);
}
