/*
 * HTTP/2 (Akamai-style) and HTTP/3 connection fingerprints, without
 * patching nginx: the v2/v3 parsers discard the client SETTINGS /
 * PRIORITY / pseudo-header ordering, so we tee the cleartext byte
 * stream off c->recv and parse the fingerprint ourselves.
 *
 * Install seams:
 *  - TLS h2: the ClientHello cb (tls.c) marks hello->h2fp; the msg
 *    callback swaps c->ssl->handler on the client's Finished — our
 *    swap runs right after nginx assigns c->recv = ngx_ssl_recv and
 *    before the first app-data read, so we wrap the recv fn there.
 *  - h2c / h3 streams: ls->handler swapped for inspected addrs.  Both
 *    TCP accepts and QUIC stream conns dispatch through it; QUIC
 *    stream conns already have c->recv = ngx_quic_stream_recv.
 *
 * Per-conn state hangs off c->pool cleanups (no ex_data on
 * ngx_connection_t); h3 pieces aggregate on the session conn's ctx.
 */

#include "ngx_http_xngin_module.h"

#if (NGX_QUIC)
#include <ngx_event_quic.h>
#endif


#define XNAP_FP_CAP      8192   /* buffered cleartext per conn */
#define XNAP_FP_H3_CAP   2048   /* per h3 stream: SETTINGS / first HEADERS
                                   prefix (pseudo-headers lead the block) */
#define XNAP_FP_SET_CAP  512    /* settings "id:val,..." text */
#define XNAP_FP_PRI_CAP  256    /* "sid:excl:dep:weight,..." text */
#define XNAP_FP_ORD_CAP  128    /* "m,a,s,p" text */
#define XNAP_FP_MAX_SETTINGS   32

/* protos */
#define XNFP_H2   0   /* h2-over-TLS conn or h2c conn */
#define XNFP_H3S  1   /* quic stream conn */
#define XNFP_H3A  2   /* quic session conn aggregate */

/* parse states */
#define XFPS_PREFACE  0
#define XFPS_HDR      1
#define XFPS_PAY      2
#define XFPS_H3_TYPE  3
#define XFPS_DONE     4
#define XFPS_BAD      5


typedef struct ngx_http_xngin_h2fp_s ngx_http_xngin_h2fp_t;

struct ngx_http_xngin_h2fp_s {
    ngx_recv_pt               saved;
    void                    (*saved_ssl)(ngx_connection_t *c);
    ngx_http_xngin_h2fp_t    *agg;      /* XNFP_H3S → session ctx */
    ngx_connection_t         *agg_conn; /* XNFP_H3A → session conn */

    u_char                   *buf;      /* captured stream prefix */
    size_t                    cap;
    size_t                    len;      /* bytes captured */
    size_t                    pos;      /* bytes consumed by parser */
    ngx_uint_t                state;
    ngx_uint_t                proto;

    uint64_t                  need;     /* payload bytes wanted */
    uint64_t                  ftype, fflags, fsid;

    u_char                    set[XNAP_FP_SET_CAP];
    ngx_uint_t                set_len;
    u_char                    pri[XNAP_FP_PRI_CAP];
    ngx_uint_t                pri_len;
    u_char                    ord[XNAP_FP_ORD_CAP];
    ngx_uint_t                ord_len;
    uint32_t                  winupd;

    unsigned                  winupd_seen:1;
    unsigned                  seen_settings:1;
    unsigned                  seen_headers:1;
    unsigned                  cont_needed:1;
    unsigned                  done:1;
    unsigned                  h3_is_control:1;
    unsigned                  trunc:1;  /* h3 HEADERS larger than buf */

    ngx_str_t                 fp;       /* result */
};


typedef struct {
    ngx_listening_t          *ls;
    void                    (*handler)(ngx_connection_t *c);
} ngx_http_xngin_ls_wrap_t;


static ngx_array_t *ngx_http_xngin_ls_wraps;   /* ngx_http_xngin_ls_wrap_t */

static void     ngx_http_xngin_h2fp_cleanup(void *data);
static ssize_t  ngx_http_xngin_h2fp_recv(ngx_connection_t *c, u_char *buf,
                    size_t size);
static void     ngx_http_xngin_h2fp_feed(ngx_connection_t *c,
                    ngx_http_xngin_h2fp_t *f);
static void     ngx_http_xngin_h2fp_frame(ngx_connection_t *c,
                    ngx_http_xngin_h2fp_t *f, u_char *p, uint32_t n);
static void     ngx_http_xngin_hpack(ngx_http_xngin_h2fp_t *f, u_char *p,
                    u_char *end);
static void     ngx_http_xngin_h3_stream(ngx_connection_t *c,
                    ngx_http_xngin_h2fp_t *f);
static void     ngx_http_xngin_qpack(ngx_http_xngin_h2fp_t *agg, u_char *p,
                    u_char *end);
static void     ngx_http_xngin_ls_handler(ngx_connection_t *c);
static void     ngx_http_xngin_ssl_wrap(ngx_connection_t *c);
static ngx_http_xngin_h2fp_t *ngx_http_xngin_h2fp_new(ngx_connection_t *c,
                    ngx_uint_t proto);
static void     ngx_http_xngin_h2fp_ord(ngx_http_xngin_h2fp_t *f, u_char ch);
static void     ngx_http_xngin_h2fp_done(ngx_connection_t *c,
                    ngx_http_xngin_h2fp_t *f);
static void     ngx_http_xngin_h3_agg_done(ngx_http_xngin_h2fp_t *agg);
static ngx_int_t ngx_http_xngin_pfx_int(u_char **pp, u_char *end,
                    unsigned pfx, uint64_t *out);
static ngx_int_t ngx_http_xngin_lit_skip(u_char **pp, u_char *end,
                    unsigned pfx);
static ngx_int_t ngx_http_xngin_lit_name(u_char **pp, u_char *end,
                    unsigned pfx, u_char *letter);
static u_char   ngx_http_xngin_h2_letter(uint64_t idx);
static u_char   ngx_http_xngin_qpack_letter(uint64_t idx);
static u_char   ngx_http_xngin_name_letter(u_char *p, size_t n);


/* ---------- ctx storage: pool cleanup walk ---------- */

static void
ngx_http_xngin_h2fp_cleanup(void *data)
{
    /* everything lives in the connection pool; nothing to free */
    (void) data;
}


static ngx_http_xngin_h2fp_t *
ngx_http_xngin_h2fp_find(ngx_connection_t *c)
{
    ngx_pool_cleanup_t *cln;

    if (c->pool == NULL) {
        return NULL;
    }

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_xngin_h2fp_cleanup) {
            return cln->data;
        }
    }

    return NULL;
}


static ngx_http_xngin_h2fp_t *
ngx_http_xngin_h2fp_new(ngx_connection_t *c, ngx_uint_t proto)
{
    ngx_pool_cleanup_t       *cln;
    ngx_http_xngin_h2fp_t    *f;

    f = ngx_http_xngin_h2fp_find(c);
    if (f == NULL) {
        if (c->pool == NULL) {
            return NULL;
        }

        cln = ngx_pool_cleanup_add(c->pool, sizeof(ngx_http_xngin_h2fp_t));
        if (cln == NULL) {
            return NULL;
        }

        f = cln->data;
        ngx_memzero(f, sizeof(ngx_http_xngin_h2fp_t));
        cln->handler = ngx_http_xngin_h2fp_cleanup;
    }

    f->proto = proto;
    return f;
}


static ngx_int_t
ngx_http_xngin_h2fp_buf(ngx_connection_t *c, ngx_http_xngin_h2fp_t *f,
    size_t cap)
{
    if (f->buf == NULL) {
        f->buf = ngx_pnalloc(c->pool, cap);
        if (f->buf == NULL) {
            return NGX_ERROR;
        }
        f->cap = cap;
    }
    return NGX_OK;
}


/* ---------- recv tee ---------- */

void
ngx_http_xngin_h2fp_attach(ngx_connection_t *c)
{
    ngx_http_xngin_h2fp_t *f;

    if (c->recv == ngx_http_xngin_h2fp_recv) {
        return;
    }

    f = ngx_http_xngin_h2fp_new(c, XNFP_H2);
    if (f == NULL || ngx_http_xngin_h2fp_buf(c, f, XNAP_FP_CAP) != NGX_OK) {
        return;
    }

    f->saved = c->recv;
    c->recv = ngx_http_xngin_h2fp_recv;
}


/* ClientHello cb marked hello->h2fp; the Finished inbound handshake
   msg is the earliest point where c->ssl->handler is already assigned
   (nginx sets it after the first SSL_do_handshake) — swap it so we
   wrap c->recv once it becomes ngx_ssl_recv */
void
ngx_http_xngin_h2fp_ssl_hook(ngx_connection_t *c)
{
    ngx_http_xngin_h2fp_t *f;

    if (c->ssl == NULL || c->ssl->handler == NULL) {
        return;
    }

#if (NGX_QUIC)
    /* QUIC session conns init streams through ssl->handler — the h3
       path tees stream conns via the ls->handler swap instead */
    if (c->listening != NULL && c->listening->quic) {
        return;
    }
#endif

    f = ngx_http_xngin_h2fp_new(c, XNFP_H2);
    if (f == NULL || f->saved_ssl != NULL) {
        return;
    }

    f->saved_ssl = c->ssl->handler;
    c->ssl->handler = ngx_http_xngin_ssl_wrap;
}


static void
ngx_http_xngin_ssl_wrap(ngx_connection_t *c)
{
    ngx_http_xngin_h2fp_t   *f;
    void                   (*handler)(ngx_connection_t *c);

    f = ngx_http_xngin_h2fp_find(c);
    handler = f ? f->saved_ssl : NULL;

    /* c->recv is ngx_ssl_recv now — tee the decrypted stream */
    if (f) {
        ngx_http_xngin_h2fp_attach(c);
    }

    if (handler) {
        handler(c);
    }
}


static ssize_t
ngx_http_xngin_h2fp_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    size_t                  m;
    ssize_t                 n;
    ngx_recv_pt             saved;
    ngx_http_xngin_h2fp_t  *f;

    f = ngx_http_xngin_h2fp_find(c);
    if (f == NULL || f->saved == NULL) {
        return NGX_ERROR;
    }

    saved = f->saved;
    n = saved(c, buf, size);

    if (n > 0 && !f->done && f->state != XFPS_BAD
        && f->state != XFPS_DONE)
    {
        /* copy what fits: an h3 HEADERS prefix is still parseable */
        m = ngx_min((size_t) n, f->cap - f->len);
        ngx_memcpy(f->buf + f->len, buf, m);
        f->len += m;
        ngx_http_xngin_h2fp_feed(c, f);

        if (m < (size_t) n && f->state != XFPS_DONE) {
            f->state = XFPS_BAD;   /* fingerprint window exceeded */
        }
    }

    /* nothing more to learn — drop the tee for the rest of the conn */
    if ((f->state == XFPS_BAD || f->state == XFPS_DONE)
        && c->recv == ngx_http_xngin_h2fp_recv)
    {
        c->recv = saved;
        f->saved = NULL;
    }

    return n;
}


/* ---------- shared fp assembly ---------- */

static void
ngx_http_xngin_h2fp_ord(ngx_http_xngin_h2fp_t *f, u_char ch)
{
    if (f->ord_len + 2 <= XNAP_FP_ORD_CAP) {
        if (f->ord_len) {
            f->ord[f->ord_len++] = ',';
        }
        f->ord[f->ord_len++] = ch;
    }
}


/* Akamai format: settings|window_update|priorities|pseudo_header_order */
static void
ngx_http_xngin_h2fp_done(ngx_connection_t *c, ngx_http_xngin_h2fp_t *f)
{
    u_char *p;
    size_t  len;

    if (f->done) {
        return;
    }
    f->done = 1;

    len = f->set_len + 1 + 12 + 1 + (f->pri_len ? f->pri_len : 1) + 1
          + f->ord_len;

    f->fp.data = ngx_pnalloc(c->pool, len);
    if (f->fp.data == NULL) {
        return;
    }

    p = f->fp.data;
    p = ngx_cpymem(p, f->set, f->set_len);
    *p++ = '|';
    p = ngx_snprintf(p, 12, "%uD", f->winupd);
    *p++ = '|';
    if (f->pri_len) {
        p = ngx_cpymem(p, f->pri, f->pri_len);
    } else {
        *p++ = '0';
    }
    *p++ = '|';
    p = ngx_cpymem(p, f->ord, f->ord_len);

    f->fp.len = p - f->fp.data;

    /* nothing left to see — restore the conn's original recv fn */
    if (f->saved != NULL && c->recv == ngx_http_xngin_h2fp_recv) {
        c->recv = f->saved;
        f->saved = NULL;
    }
}


static void
ngx_http_xngin_h3_agg_done(ngx_http_xngin_h2fp_t *agg)
{
    u_char             *p;
    size_t              len;
    ngx_connection_t   *c;

    if (agg->done || agg->agg_conn == NULL) {
        return;
    }
    agg->done = 1;
    c = agg->agg_conn;

    len = agg->set_len + 1 + agg->ord_len;
    agg->fp.data = ngx_pnalloc(c->pool, len);
    if (agg->fp.data == NULL) {
        return;
    }

    p = agg->fp.data;
    p = ngx_cpymem(p, agg->set, agg->set_len);
    *p++ = '|';
    p = ngx_cpymem(p, agg->ord, agg->ord_len);
    agg->fp.len = p - agg->fp.data;
}


/* ---------- varint / prefix-int decoders ---------- */

/* HPACK/QPACK N-bit-prefix integer */
static ngx_int_t
ngx_http_xngin_pfx_int(u_char **pp, u_char *end, unsigned pfx,
    uint64_t *out)
{
    uint64_t  v, m;
    u_char   *p = *pp;
    unsigned  i;

    if (p >= end) {
        return NGX_ERROR;
    }

    v = *p & ((1 << pfx) - 1);
    p++;

    if (v < (uint64_t) ((1 << pfx) - 1)) {
        *pp = p;
        *out = v;
        return NGX_OK;
    }

    m = 0;
    for (i = 0; i < 10 && p < end; i++) {
        v += (uint64_t) (*p & 0x7f) << m;
        m += 7;
        if (!(*p++ & 0x80)) {
            *pp = p;
            *out = v;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}


/* skip one literal string (H flag + prefix len + bytes) */
static ngx_int_t
ngx_http_xngin_lit_skip(u_char **pp, u_char *end, unsigned pfx)
{
    uint64_t  n;
    u_char   *p = *pp;

    if (ngx_http_xngin_pfx_int(&p, end, pfx, &n) != NGX_OK) {
        return NGX_ERROR;
    }
    if ((uint64_t) (end - p) < n) {
        return NGX_ERROR;
    }

    *pp = p + n;
    return NGX_OK;
}


/* read a literal field name: plain names map to pseudo letters,
   huffman-coded names are skipped (letter 0).  consumes name bytes */
static ngx_int_t
ngx_http_xngin_lit_name(u_char **pp, u_char *end, unsigned pfx,
    u_char *letter)
{
    uint64_t  n;
    unsigned  huff;
    u_char   *p = *pp;

    *letter = 0;

    if (p >= end) {
        return NGX_ERROR;
    }

    huff = *p & 0x80;
    if (ngx_http_xngin_pfx_int(&p, end, pfx, &n) != NGX_OK) {
        return NGX_ERROR;
    }
    if ((uint64_t) (end - p) < n) {
        return NGX_ERROR;
    }

    if (!huff && n && n <= 10) {
        *letter = ngx_http_xngin_name_letter(p, n);
    }

    *pp = p + n;
    return NGX_OK;
}


/* ---------- h2 frame parser ---------- */

/* HPACK static-table indices for the four pseudo headers */
static u_char
ngx_http_xngin_h2_letter(uint64_t idx)
{
    switch (idx) {
        case 1:            return 'a';   /* :authority */
        case 2: case 3:    return 'm';   /* :method */
        case 4: case 5:    return 'p';   /* :path */
        case 6: case 7:    return 's';   /* :scheme */
    }
    return 0;
}


static u_char
ngx_http_xngin_name_letter(u_char *p, size_t n)
{
    static const u_char an[] = ":authority";
    static const u_char me[] = ":method";
    static const u_char pa[] = ":path";
    static const u_char sc[] = ":scheme";

    if (n == sizeof(an) - 1 && ngx_memcmp(p, an, n) == 0) { return 'a'; }
    if (n == sizeof(me) - 1 && ngx_memcmp(p, me, n) == 0) { return 'm'; }
    if (n == sizeof(pa) - 1 && ngx_memcmp(p, pa, n) == 0) { return 'p'; }
    if (n == sizeof(sc) - 1 && ngx_memcmp(p, sc, n) == 0) { return 's'; }
    return 0;
}


/* HPACK-lite over one header-block fragment: only pseudo-header order
   matters; everything else is skipped field-line by field-line */
static void
ngx_http_xngin_hpack(ngx_http_xngin_h2fp_t *f, u_char *p, u_char *end)
{
    uint64_t  idx, d;
    u_char    b, letter;
    u_char    dyn[64];        /* letters of dyn entries 62..125 */
    unsigned  dyn_next = 0;

    ngx_memzero(dyn, sizeof(dyn));

    while (p < end) {
        b = *p;

        if (b & 0x80) {                       /* indexed */
            if (ngx_http_xngin_pfx_int(&p, end, 7, &idx) != NGX_OK) {
                return;
            }
            if (idx > 61) {
                d = idx - 62;
                letter = (d < sizeof(dyn)) ? dyn[d] : 0;
            } else {
                letter = ngx_http_xngin_h2_letter(idx);
            }
            if (letter) {
                ngx_http_xngin_h2fp_ord(f, letter);
            }
            continue;
        }

        if ((b & 0xe0) == 0x20) {             /* dyn table size update */
            if (ngx_http_xngin_pfx_int(&p, end, 5, &idx) != NGX_OK) {
                return;
            }
            continue;
        }

        /* 01xxxxxx incremental / 0000xxxx / 0001xxxx literal families */
        if (ngx_http_xngin_pfx_int(&p, end, (b & 0x40) ? 6 : 4, &idx)
            != NGX_OK)
        {
            return;
        }

        if (idx == 0) {
            if (ngx_http_xngin_lit_name(&p, end, 7, &letter) != NGX_OK) {
                return;
            }
        } else if (idx <= 61) {
            letter = ngx_http_xngin_h2_letter(idx);
        } else {
            d = idx - 62;
            letter = (d < sizeof(dyn)) ? dyn[d] : 0;
        }

        if (letter) {
            ngx_http_xngin_h2fp_ord(f, letter);
        }

        /* literal-with-incremental-indexing appends the name to the
           dynamic table — remember pseudo names for later refs */
        if (b & 0x40) {
            if (letter && dyn_next < sizeof(dyn)) {
                dyn[dyn_next] = letter;
            }
            dyn_next++;
        }

        if (ngx_http_xngin_lit_skip(&p, end, 7) != NGX_OK) {  /* value */
            return;
        }
    }
}


static void
ngx_http_xngin_h2fp_frame(ngx_connection_t *c, ngx_http_xngin_h2fp_t *f,
    u_char *p, uint32_t n)
{
    uint64_t  sid = f->fsid & 0x7fffffff;

    if (f->seen_headers) {
        /* only CONTINUATION payloads still matter */
        if (f->ftype == 0x9 && f->cont_needed) {
            ngx_http_xngin_hpack(f, p, p + n);
            if (f->fflags & 0x4) {
                ngx_http_xngin_h2fp_done(c, f);
            }
        }
        return;
    }

    switch (f->ftype) {

    case 0x4:                                    /* SETTINGS */
        if (sid || f->seen_settings || (f->fflags & 0x1)) {
            break;
        }
        f->seen_settings = 1;
        {
            uint32_t  cnt = 0;
            u_char   *e = p + n;

            while (p + 6 <= e && cnt++ < XNAP_FP_MAX_SETTINGS) {
                uint16_t  id = ((uint16_t) p[0] << 8) | p[1];
                uint32_t  v  = ((uint32_t) p[2] << 24) | (p[3] << 16)
                               | (p[4] << 8) | p[5];
                u_char    tmp[16];
                size_t    tl;

                tl = ngx_snprintf(tmp, sizeof(tmp), "%uD:%uD",
                                  (uint32_t) id, v) - tmp;
                if (f->set_len + 1 + tl <= XNAP_FP_SET_CAP) {
                    if (f->set_len) {
                        f->set[f->set_len++] = ',';
                    }
                    ngx_memcpy(f->set + f->set_len, tmp, tl);
                    f->set_len += tl;
                }
                p += 6;
            }
        }
        break;

    case 0x8:                                    /* WINDOW_UPDATE */
        if (sid == 0 && !f->winupd_seen && n >= 4) {
            f->winupd = (((uint32_t) p[0] & 0x7f) << 24) | (p[1] << 16)
                        | ((uint32_t) p[2] << 8) | p[3];
            f->winupd_seen = 1;
        }
        break;

    case 0x2:                                    /* PRIORITY */
        if (n >= 5) {
            u_char    tmp[32];
            size_t    tl;
            uint32_t  dep;

            dep = ((uint32_t) p[0] << 24) | (p[1] << 16)
                  | ((uint32_t) p[2] << 8) | p[3];
            tl = ngx_snprintf(tmp, sizeof(tmp), "%uD:%d:%uD:%d",
                              (uint32_t) sid, (dep & 0x80000000) ? 1 : 0,
                              dep & 0x7fffffff, p[4] + 1) - tmp;
            if (f->pri_len + (f->pri_len ? 1 : 0) + tl
                <= XNAP_FP_PRI_CAP)
            {
                if (f->pri_len) {
                    f->pri[f->pri_len++] = ',';
                }
                ngx_memcpy(f->pri + f->pri_len, tmp, tl);
                f->pri_len += tl;
            }
        }
        break;

    case 0x1:                                    /* HEADERS */
        {
            uint64_t pad = 0;

            f->seen_headers = 1;
            f->cont_needed = !(f->fflags & 0x4);

            if (f->fflags & 0x8) {               /* PADDED */
                if (n < 1) {
                    break;
                }
                pad = *p++;
                n--;
            }
            if (f->fflags & 0x20) {              /* PRIORITY section */
                if (n < 5) {
                    break;
                }
                p += 5;
                n -= 5;
            }
            if (pad < n) {
                ngx_http_xngin_hpack(f, p, p + n - pad);
            }
            if (f->fflags & 0x4) {
                ngx_http_xngin_h2fp_done(c, f);
            }
        }
        break;
    }
}


static void
ngx_http_xngin_h2fp_feed(ngx_connection_t *c, ngx_http_xngin_h2fp_t *f)
{
    static const u_char preface[] =
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";          /* 24 bytes */

    if (f->proto == XNFP_H3S) {
        ngx_http_xngin_h3_stream(c, f);
        return;
    }

    while (f->pos < f->len && f->state != XFPS_DONE
           && f->state != XFPS_BAD)
    {
        if (f->state == XFPS_PREFACE) {
            while (f->pos < f->len && f->pos < sizeof(preface) - 1) {
                if (f->buf[f->pos] != preface[f->pos]) {
                    f->state = XFPS_BAD;
                    return;
                }
                f->pos++;
            }
            if (f->pos == sizeof(preface) - 1) {
                f->state = XFPS_HDR;
            }
            continue;
        }

        if (f->state == XFPS_HDR) {
            u_char *h;

            if (f->len - f->pos < 9) {
                return;
            }
            h = f->buf + f->pos;
            f->need   = ((uint64_t) h[0] << 16) | (h[1] << 8) | h[2];
            f->ftype  = h[3];
            f->fflags = h[4];
            f->fsid   = ((uint64_t) (h[5] & 0x7f) << 24)
                        | ((uint64_t) h[6] << 16)
                        | ((uint64_t) h[7] << 8) | h[8];
            f->pos   += 9;

            if (f->need > f->cap - f->pos) {
                f->state = XFPS_BAD;   /* frame won't fit the window */
                return;
            }
            f->state = XFPS_PAY;
            continue;
        }

        /* XFPS_PAY */
        if (f->len - f->pos < f->need) {
            return;
        }
        ngx_http_xngin_h2fp_frame(c, f, f->buf + f->pos,
                                (uint32_t) f->need);
        f->pos += f->need;
        f->state = (f->done ? XFPS_DONE : XFPS_HDR);
    }
}


/* ---------- h3 stream parser (quic varint frames) ---------- */

/* RFC 9204 static-table pseudo-header entries */
static u_char
ngx_http_xngin_qpack_letter(uint64_t idx)
{
    if (idx == 0)               { return 'a'; }   /* :authority */
    if (idx == 1)               { return 'p'; }   /* :path / */
    if (idx >= 15 && idx <= 21) { return 'm'; }   /* :method */
    if (idx == 22 || idx == 23) { return 's'; }   /* :scheme */
    return 0;
}


/* QPACK-lite over one field section: pseudo-header order only.
   Dynamic/post-base refs can't be pseudo entries on a first request
   (the dyn table starts empty), so they are skipped */
static void
ngx_http_xngin_qpack(ngx_http_xngin_h2fp_t *agg, u_char *p, u_char *end)
{
    uint64_t  v;
    u_char    b, letter;

    /* field-section prefix: RequiredInsertCount(8) + Base(7) */
    if (ngx_http_xngin_pfx_int(&p, end, 8, &v) != NGX_OK) {
        return;
    }
    if (ngx_http_xngin_pfx_int(&p, end, 7, &v) != NGX_OK) {
        return;
    }

    while (p < end) {
        b = *p;

        if (b & 0x80) {                       /* indexed field line */
            if (ngx_http_xngin_pfx_int(&p, end, 6, &v) != NGX_OK) {
                return;
            }
            if (b & 0x40) {                   /* static */
                letter = ngx_http_xngin_qpack_letter(v);
                if (letter) {
                    ngx_http_xngin_h2fp_ord(agg, letter);
                }
            }
            continue;
        }

        if (b & 0x40) {                       /* literal, name ref */
            if (ngx_http_xngin_pfx_int(&p, end, 4, &v) != NGX_OK) {
                return;
            }
            if (b & 0x10) {                   /* static */
                letter = ngx_http_xngin_qpack_letter(v);
                if (letter) {
                    ngx_http_xngin_h2fp_ord(agg, letter);
                }
            }
            if (ngx_http_xngin_lit_skip(&p, end, 7) != NGX_OK) {
                return;
            }
            continue;
        }

        if ((b & 0xe0) == 0x20) {             /* literal, literal name */
            /* name length (3-bit prefix) + huff bit 0x08 packed in b */
            uint64_t  n = b & 7;
            unsigned  m, i;

            p++;
            if (n == 7) {
                m = 0;
                for (i = 0; i < 10 && p < end; i++) {
                    n += (uint64_t) (*p & 0x7f) << m;
                    m += 7;
                    if (!(*p++ & 0x80)) {
                        break;
                    }
                }
            }
            if ((uint64_t) (end - p) < n) {
                return;
            }
            letter = 0;
            if (!(b & 0x08) && n && n <= 10) {
                letter = ngx_http_xngin_name_letter(p, n);
            }
            p += n;
            if (letter) {
                ngx_http_xngin_h2fp_ord(agg, letter);
            }
            if (ngx_http_xngin_lit_skip(&p, end, 7) != NGX_OK) {
                return;
            }
            continue;
        }

        if ((b & 0xf0) == 0x10) {             /* indexed post-base */
            if (ngx_http_xngin_pfx_int(&p, end, 4, &v) != NGX_OK) {
                return;
            }
            continue;
        }

        /* 0000Nxxx literal with post-base name ref */
        if (ngx_http_xngin_pfx_int(&p, end, 3, &v) != NGX_OK) {
            return;
        }
        if (ngx_http_xngin_lit_skip(&p, end, 7) != NGX_OK) {
            return;
        }
    }
}


static void
ngx_http_xngin_h3_stream(ngx_connection_t *c, ngx_http_xngin_h2fp_t *f)
{
    ngx_http_xngin_h2fp_t  *agg = f->agg;

    while (f->pos < f->len && f->state != XFPS_DONE
           && f->state != XFPS_BAD)
    {
        if (f->state == XFPS_H3_TYPE) {
            u_char   *p;
            uint64_t  t;

#if (NGX_QUIC)
            {
                ngx_quic_stream_t *qs = c->quic;

                if (qs && !(qs->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)) {
                    /* request stream: no type varint, straight to frames */
                    f->state = XFPS_HDR;
                    continue;
                }
            }
#endif
            p = f->buf + f->pos;
            t = ngx_http_xngin_qvarint(&p, f->buf + f->len);
            if (t == (uint64_t) -1) {
                return;
            }
            f->pos = p - f->buf;
            f->h3_is_control = (t == 0x00);

            /* encoder(0x02)/decoder(0x03)/push streams carry no fp data */
            if (!f->h3_is_control) {
                f->state = XFPS_DONE;
                return;
            }
            f->state = XFPS_HDR;
            continue;
        }

        if (f->state == XFPS_HDR) {
            u_char   *p;
            uint64_t  t, n;

            p = f->buf + f->pos;
            t = ngx_http_xngin_qvarint(&p, f->buf + f->len);
            if (t == (uint64_t) -1) {
                return;
            }
            n = ngx_http_xngin_qvarint(&p, f->buf + f->len);
            if (n == (uint64_t) -1) {
                return;
            }
            f->ftype = t;
            f->need  = n;
            f->pos   = p - f->buf;

            if (f->need > f->cap - f->pos) {
                if (f->h3_is_control || f->ftype != 0x01) {
                    f->state = XFPS_BAD;
                    return;
                }
                /* oversized first HEADERS: pseudo-headers lead the
                   field section, so the buffered prefix suffices */
                f->trunc = 1;
            }
            f->state = XFPS_PAY;
            continue;
        }

        /* XFPS_PAY */
        if (f->len - f->pos < f->need) {
            if (!f->trunc || f->len < f->cap) {
                return;
            }
            f->need = f->len - f->pos;
        }

        if (agg == NULL) {
            f->state = XFPS_BAD;
            return;
        }

        if (f->h3_is_control) {
            if (f->ftype == 0x04 && !agg->seen_settings) {   /* SETTINGS */
                u_char   *p, *e;
                unsigned  cnt = 0;

                agg->seen_settings = 1;
                p = f->buf + f->pos;
                e = p + f->need;
                while (p < e && cnt++ < XNAP_FP_MAX_SETTINGS) {
                    uint64_t  id, v;
                    u_char    tmp[24];
                    size_t    tl;

                    id = ngx_http_xngin_qvarint(&p, e);
                    if (id == (uint64_t) -1) {
                        break;
                    }
                    v = ngx_http_xngin_qvarint(&p, e);
                    if (v == (uint64_t) -1) {
                        break;
                    }
                    tl = ngx_snprintf(tmp, sizeof(tmp), "%uL:%uL",
                                      id, v) - tmp;
                    if (agg->set_len + 1 + tl <= XNAP_FP_SET_CAP) {
                        if (agg->set_len) {
                            agg->set[agg->set_len++] = ',';
                        }
                        ngx_memcpy(agg->set + agg->set_len, tmp, tl);
                        agg->set_len += tl;
                    }
                }
            }
        } else if (f->ftype == 0x01) {                       /* HEADERS */
            if (!agg->seen_headers) {
                agg->seen_headers = 1;
                ngx_http_xngin_qpack(agg, f->buf + f->pos,
                                     f->buf + f->pos + f->need);
            }
        }

        if (agg->set_len && agg->ord_len) {
            ngx_http_xngin_h3_agg_done(agg);
        }

        f->pos += f->need;

        /* control stream: SETTINGS is its only fp frame; request
           stream: only the first HEADERS matters — stop teeing */
        if ((f->h3_is_control && f->ftype == 0x04)
            || (!f->h3_is_control && f->ftype == 0x01))
        {
            f->state = XFPS_DONE;
            return;
        }
        f->state = XFPS_HDR;
    }
}


/* ---------- ls->handler swap ---------- */

static void
ngx_http_xngin_ls_handler(ngx_connection_t *c)
{
    ngx_uint_t                 i;
    ngx_http_xngin_ls_wrap_t  *w;
    void                     (*handler)(ngx_connection_t *c) = NULL;

    if (ngx_http_xngin_ls_wraps) {
        w = ngx_http_xngin_ls_wraps->elts;
        for (i = 0; i < ngx_http_xngin_ls_wraps->nelts; i++) {
            if (w[i].ls == c->listening) {
                handler = w[i].handler;
                break;
            }
        }
    }

#if (NGX_QUIC)
    if (c->listening->quic) {
        if (c->quic) {
            /* stream conn: tee the quic stream recv; the fingerprint
               aggregates on the session conn's pool ctx */
            ngx_http_xngin_h2fp_t  *f, *agg;
            ngx_connection_t       *pc;
            ngx_quic_stream_t      *qs = c->quic;

            pc = qs->parent;
            agg = pc ? ngx_http_xngin_h2fp_find(pc) : NULL;

            /* session already has what this stream could add: the
               control SETTINGS (uni) / first request HEADERS (bidi) —
               later streams pay nothing */
            if (agg != NULL
                && (agg->done
                    || ((qs->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)
                        ? agg->seen_settings : agg->seen_headers)))
            {
                goto next;
            }

            f = ngx_http_xngin_h2fp_new(c, XNFP_H3S);
            agg = pc ? ngx_http_xngin_h2fp_new(pc, XNFP_H3A) : NULL;
            if (f && agg) {
                agg->agg_conn = pc;
                f->agg = agg;
                f->state = XFPS_H3_TYPE;
                if (ngx_http_xngin_h2fp_buf(c, f, XNAP_FP_H3_CAP) == NGX_OK
                    && c->recv != ngx_http_xngin_h2fp_recv)
                {
                    f->saved = c->recv;
                    c->recv = ngx_http_xngin_h2fp_recv;
                }
            }
        }
        /* c->quic == NULL: the session conn itself — datagram-level
           recv, nothing to fingerprint */
    } else
#endif
    {
        ngx_http_xngin_h2fp_attach(c);
    }

#if (NGX_QUIC)
next:
#endif

    if (handler) {
        handler(c);
    }
}


/* init_module hook: listeners exist (ngx_http_optimize_servers runs
   after http postconfig), ls->handler and ls->servers are populated */
ngx_int_t
ngx_http_xngin_h2fp_init(ngx_cycle_t *cycle)
{
    ngx_listening_t               *ls;
    ngx_http_port_t               *hport;
    ngx_http_in_addr_t            *addr;
#if (NGX_HAVE_INET6)
    ngx_http_in6_addr_t           *addr6;
#endif
    ngx_http_xngin_srv_conf_t     *xscf;
    ngx_http_xngin_ls_wrap_t      *w;
    ngx_uint_t                     i, a, want, clr;

    ngx_http_xngin_ls_wraps = NULL;

    ls = cycle->listening.elts;

    for (i = 0; i < cycle->listening.nelts; i++) {
        /* http listeners only — a stream{} ls->servers is a different
           port struct type */
        if (ls[i].handler != ngx_http_init_connection) {
            continue;
        }

        hport = ls[i].servers;
        if (hport == NULL || hport->naddrs == 0) {
            continue;
        }

        want = 0;
        clr = 0;

#if (NGX_HAVE_INET6)
        if (ls[i].sockaddr->sa_family == AF_INET6) {
            addr6 = hport->addrs;
            for (a = 0; a < hport->naddrs; a++) {
                xscf = addr6[a].conf.default_server->ctx
                       ->srv_conf[ngx_http_xngin_module.ctx_index];
                if (xscf && xscf->h2_inspect) {
                    want = 1;
                }
                if (!addr6[a].conf.ssl) {
                    clr = 1;
                }
            }
        } else
#endif
        {
            addr = hport->addrs;
            for (a = 0; a < hport->naddrs; a++) {
                xscf = addr[a].conf.default_server->ctx
                       ->srv_conf[ngx_http_xngin_module.ctx_index];
                if (xscf && xscf->h2_inspect) {
                    want = 1;
                }
                if (!addr[a].conf.ssl) {
                    clr = 1;
                }
            }
        }

        if (!want) {
            continue;
        }

#if (NGX_QUIC)
        if (!ls[i].quic && !clr) {
            /* TLS addrs are covered by the ssl->handler swap instead —
               wrapping ngx_recv at init would only see ciphertext */
            continue;
        }
#else
        if (!clr) {
            continue;
        }
#endif

        if (ngx_http_xngin_ls_wraps == NULL) {
            ngx_http_xngin_ls_wraps =
                ngx_array_create(cycle->pool, 4,
                                 sizeof(ngx_http_xngin_ls_wrap_t));
            if (ngx_http_xngin_ls_wraps == NULL) {
                return NGX_ERROR;
            }
        }

        w = ngx_array_push(ngx_http_xngin_ls_wraps);
        if (w == NULL) {
            return NGX_ERROR;
        }

        w->ls = &ls[i];
        w->handler = ls[i].handler;
        ls[i].handler = ngx_http_xngin_ls_handler;
    }

    return NGX_OK;
}


/* ---------- accessors ---------- */

ngx_str_t *
ngx_http_xngin_h2fp_get(ngx_connection_t *c)
{
    ngx_http_xngin_h2fp_t *f;

    f = ngx_http_xngin_h2fp_find(c);
    if (f == NULL || f->fp.len == 0) {
        return NULL;
    }
    return &f->fp;
}


ngx_str_t *
ngx_http_xngin_h3fp_get(ngx_connection_t *c)
{
#if (NGX_QUIC)
    ngx_connection_t       *pc;
    ngx_http_xngin_h2fp_t  *agg;

    if (c->quic == NULL) {
        return NULL;
    }

    pc = ((ngx_quic_stream_t *) c->quic)->parent;
    if (pc == NULL) {
        return NULL;
    }

    agg = ngx_http_xngin_h2fp_find(pc);
    if (agg == NULL || agg->fp.len == 0) {
        return NULL;
    }
    return &agg->fp;
#else
    return NULL;
#endif
}
