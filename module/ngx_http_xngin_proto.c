#include "ngx_http_xngin_module.h"


void
ngx_xnap_wbuf_init(ngx_xnap_wbuf_t *wb, ngx_pool_t *pool, size_t cap)
{
    wb->start = ngx_palloc(pool, cap);
    wb->pos = wb->start;
    wb->end = wb->start + cap;
    wb->pool = pool;
}


static ngx_int_t
ngx_xnap_wbuf_ensure(ngx_xnap_wbuf_t *wb, size_t n)
{
    size_t   size, used;
    u_char  *p;

    if ((size_t) (wb->end - wb->pos) >= n) {
        return NGX_OK;
    }

    used = wb->pos - wb->start;
    size = (wb->end - wb->start) * 2;

    while (size - used < n) {
        size *= 2;
    }

    p = ngx_palloc(wb->pool, size);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, wb->start, used);
    wb->start = p;
    wb->pos = p + used;
    wb->end = p + size;

    return NGX_OK;
}


ngx_int_t
ngx_xnap_wbuf_u8(ngx_xnap_wbuf_t *wb, u_char b)
{
    if (ngx_xnap_wbuf_ensure(wb, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    *wb->pos++ = b;
    return NGX_OK;
}


ngx_int_t
ngx_xnap_wbuf_bytes(ngx_xnap_wbuf_t *wb, const void *p, size_t n)
{
    if (ngx_xnap_wbuf_ensure(wb, n) != NGX_OK) {
        return NGX_ERROR;
    }

    wb->pos = ngx_cpymem(wb->pos, p, n);
    return NGX_OK;
}


size_t
ngx_xnap_varint_len(uint64_t v)
{
    size_t n = 1;

    while (v >= 0x80) {
        v >>= 7;
        n++;
    }

    return n;
}


ngx_int_t
ngx_xnap_wbuf_varint(ngx_xnap_wbuf_t *wb, uint64_t v)
{
    if (ngx_xnap_wbuf_ensure(wb, 10) != NGX_OK) {
        return NGX_ERROR;
    }

    while (v >= 0x80) {
        *wb->pos++ = (u_char) (v | 0x80);
        v >>= 7;
    }

    *wb->pos++ = (u_char) v;
    return NGX_OK;
}


ngx_int_t
ngx_xnap_wbuf_svarint(ngx_xnap_wbuf_t *wb, int64_t v)
{
    return ngx_xnap_wbuf_varint(wb, ((uint64_t) v << 1) ^ (uint64_t) (v >> 63));
}


ngx_int_t
ngx_xnap_wbuf_kv_name(ngx_xnap_wbuf_t *wb, const char *name)
{
    size_t len = ngx_strlen(name);

    if (ngx_xnap_wbuf_varint(wb, len) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_xnap_wbuf_bytes(wb, name, len);
}


ngx_int_t
ngx_xnap_wbuf_kv_str(ngx_xnap_wbuf_t *wb, const char *name,
    const void *val, size_t len)
{
    if (ngx_xnap_wbuf_kv_name(wb, name) != NGX_OK
        || ngx_xnap_wbuf_u8(wb, XNAP_VT_STR) != NGX_OK
        || ngx_xnap_wbuf_varint(wb, len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return ngx_xnap_wbuf_bytes(wb, val, len);
}


ngx_int_t
ngx_xnap_wbuf_kv_uint(ngx_xnap_wbuf_t *wb, const char *name, uint64_t v)
{
    if (ngx_xnap_wbuf_kv_name(wb, name) != NGX_OK
        || ngx_xnap_wbuf_u8(wb, XNAP_VT_UINT64) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return ngx_xnap_wbuf_varint(wb, v);
}


ngx_int_t
ngx_xnap_wbuf_kv_int(ngx_xnap_wbuf_t *wb, const char *name, int64_t v)
{
    if (ngx_xnap_wbuf_kv_name(wb, name) != NGX_OK
        || ngx_xnap_wbuf_u8(wb, XNAP_VT_INT64) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return ngx_xnap_wbuf_svarint(wb, v);
}


ngx_int_t
ngx_xnap_wbuf_kv_bool(ngx_xnap_wbuf_t *wb, const char *name, unsigned v)
{
    if (ngx_xnap_wbuf_kv_name(wb, name) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_xnap_wbuf_u8(wb, v ? XNAP_VT_TRUE : XNAP_VT_FALSE);
}


ngx_int_t
ngx_xnap_wbuf_kv_ip(ngx_xnap_wbuf_t *wb, const char *name, struct sockaddr *sa)
{
    if (ngx_xnap_wbuf_kv_name(wb, name) != NGX_OK) {
        return NGX_ERROR;
    }

    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;

        if (ngx_xnap_wbuf_u8(wb, XNAP_VT_IPV4) != NGX_OK) {
            return NGX_ERROR;
        }

        return ngx_xnap_wbuf_bytes(wb, &sin->sin_addr, 4);
    }

#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;

        if (ngx_xnap_wbuf_u8(wb, XNAP_VT_IPV6) != NGX_OK) {
            return NGX_ERROR;
        }

        return ngx_xnap_wbuf_bytes(wb, &sin6->sin6_addr, 16);
    }
#endif

    return NGX_ERROR;
}


/* ---------- reader ---------- */

uint64_t
ngx_xnap_rbuf_varint(ngx_xnap_rbuf_t *rb)
{
    uint64_t  v = 0;
    unsigned  shift = 0;
    u_char    b;

    while (rb->pos < rb->end && shift < 70) {
        b = *rb->pos++;
        v |= (uint64_t) (b & 0x7f) << shift;

        if (!(b & 0x80)) {
            return v;
        }

        shift += 7;
    }

    rb->err = 1;
    return 0;
}


int64_t
ngx_xnap_rbuf_svarint(ngx_xnap_rbuf_t *rb)
{
    uint64_t v = ngx_xnap_rbuf_varint(rb);

    return (int64_t) (v >> 1) ^ -(int64_t) (v & 1);
}


static ngx_int_t
ngx_xnap_rbuf_need(ngx_xnap_rbuf_t *rb, size_t n)
{
    if ((size_t) (rb->end - rb->pos) < n) {
        rb->err = 1;
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_xnap_rbuf_val(ngx_xnap_rbuf_t *rb, ngx_xnap_val_t *v)
{
    uint64_t n;

    if (ngx_xnap_rbuf_need(rb, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(v, sizeof(ngx_xnap_val_t));
    v->type = *rb->pos++;

    switch (v->type) {

    case XNAP_VT_NULL:
    case XNAP_VT_TRUE:
    case XNAP_VT_FALSE:
        return NGX_OK;

    case XNAP_VT_INT32:
    case XNAP_VT_INT64:
        v->i = ngx_xnap_rbuf_svarint(rb);
        return rb->err ? NGX_ERROR : NGX_OK;

    case XNAP_VT_UINT32:
    case XNAP_VT_UINT64:
        v->u = ngx_xnap_rbuf_varint(rb);
        return rb->err ? NGX_ERROR : NGX_OK;

    case XNAP_VT_IPV4:
        if (ngx_xnap_rbuf_need(rb, 4) != NGX_OK) {
            return NGX_ERROR;
        }
        v->s.data = rb->pos;
        v->s.len = 4;
        rb->pos += 4;
        return NGX_OK;

    case XNAP_VT_IPV6:
        if (ngx_xnap_rbuf_need(rb, 16) != NGX_OK) {
            return NGX_ERROR;
        }
        v->s.data = rb->pos;
        v->s.len = 16;
        rb->pos += 16;
        return NGX_OK;

    case XNAP_VT_STR:
    case XNAP_VT_BIN:
    case XNAP_VT_KVL:
        n = ngx_xnap_rbuf_varint(rb);
        if (rb->err || ngx_xnap_rbuf_need(rb, (size_t) n) != NGX_OK) {
            return NGX_ERROR;
        }
        v->s.data = rb->pos;
        v->s.len = (size_t) n;
        v->sub = rb->pos;
        v->sub_len = (size_t) n;
        rb->pos += n;
        return NGX_OK;

    case XNAP_VT_STRLIST:
        n = ngx_xnap_rbuf_varint(rb);  /* count */
        if (rb->err) {
            return NGX_ERROR;
        }
        v->u = n;
        v->sub = rb->pos;
        /* validate + measure */
        {
            ngx_xnap_rbuf_t  tmp;
            ngx_str_t        s;
            uint64_t         i;

            tmp.pos = rb->pos;
            tmp.end = rb->end;
            tmp.err = 0;

            for (i = 0; i < n; i++) {
                if (ngx_xnap_rbuf_strlist_next(&tmp, &s) != NGX_OK) {
                    rb->err = 1;
                    return NGX_ERROR;
                }
            }

            v->sub_len = tmp.pos - rb->pos;
            rb->pos = tmp.pos;
        }
        return NGX_OK;

    default:
        rb->err = 1;
        return NGX_ERROR;
    }
}


ngx_int_t
ngx_xnap_rbuf_kv(ngx_xnap_rbuf_t *rb, ngx_str_t *name, ngx_xnap_val_t *v)
{
    uint64_t n;

    if (rb->pos >= rb->end) {
        return NGX_DECLINED;   /* no more entries */
    }

    n = ngx_xnap_rbuf_varint(rb);
    if (rb->err || ngx_xnap_rbuf_need(rb, (size_t) n) != NGX_OK) {
        return NGX_ERROR;
    }

    name->data = rb->pos;
    name->len = (size_t) n;
    rb->pos += n;

    return ngx_xnap_rbuf_val(rb, v);
}


ngx_int_t
ngx_xnap_rbuf_strlist_next(ngx_xnap_rbuf_t *rb, ngx_str_t *s)
{
    uint64_t n;

    n = ngx_xnap_rbuf_varint(rb);
    if (rb->err || ngx_xnap_rbuf_need(rb, (size_t) n) != NGX_OK) {
        return NGX_ERROR;
    }

    s->data = rb->pos;
    s->len = (size_t) n;
    rb->pos += n;

    return NGX_OK;
}
