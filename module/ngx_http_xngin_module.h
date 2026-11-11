#ifndef _NGX_HTTP_XNGIN_MODULE_H_INCLUDED_
#define _NGX_HTTP_XNGIN_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define XNAP_VERSION 1

/* frame types */
#define XNAP_FRAME_ENGINE_HELLO 0x01
#define XNAP_FRAME_AGENT_HELLO  0x02
#define XNAP_FRAME_DISCON       0x03
#define XNAP_FRAME_NOTIFY       0x04
#define XNAP_FRAME_VERDICT      0x05
#define XNAP_FRAME_BODY         0x06
#define XNAP_FRAME_ABORT        0x07
#define XNAP_FRAME_PING         0x08
#define XNAP_FRAME_PONG         0x09

/* value types */
#define XNAP_VT_NULL    0x00
#define XNAP_VT_TRUE    0x01
#define XNAP_VT_FALSE   0x02
#define XNAP_VT_INT32   0x03
#define XNAP_VT_INT64   0x04
#define XNAP_VT_UINT32  0x05
#define XNAP_VT_UINT64  0x06
#define XNAP_VT_IPV4    0x07
#define XNAP_VT_IPV6    0x08
#define XNAP_VT_STR     0x09
#define XNAP_VT_BIN     0x0A
#define XNAP_VT_KVL     0x0B
#define XNAP_VT_STRLIST 0x0C

/* generic stream flags */
#define XNAP_FL_FIN    0x01
#define XNAP_FL_ABORT  0x02

/* frame-specific flags */
#define XNAP_FL_NOTIFY_HAS_BODY (1 << 8)
#define XNAP_FL_NOTIFY_ASYNC    (1 << 9)
#define XNAP_FL_BODY_LAST       (1 << 8)
#define XNAP_FL_BODY_TRUNCATED  (1 << 9)

/* capabilities */
#define XNAP_CAP_BODY   0x01
#define XNAP_CAP_ASYNC  0x02
#define XNAP_CAP_VCACHE 0x04
#define XNAP_CAP_RESP   0x08

#define XNAP_DEFAULT_MAX_FRAME  16384
#define XNAP_DEFAULT_MAX_STREAM 256
#define XNAP_STREAM_TABLE_CAP   512
#define XNAP_RBUF_SIZE          65536
#define XNAP_MAX_PONG_MISSES    2
#define XNAP_RECONNECT_DELAY    1000

/* our bit in r->buffered (0x01/0x02/0x04 are SSI/SUB/COPY, 0x10+ lowlevel) */
#define NGX_HTTP_XNGIN_BUFFERED 0x08

/* verdict cache results */
#define XNAP_CACHE_DISABLED 0
#define XNAP_CACHE_MISS     1
#define XNAP_CACHE_HIT      2
#define XNAP_CACHE_BYPASS   3

/* ctx states */
#define XNAP_ST_NEW       0
#define XNAP_ST_SENT      1
#define XNAP_ST_DONE      2
#define XNAP_ST_TIMEDOUT  3
#define XNAP_ST_ABORTED   4

/* fail modes */
#define XNAP_FAIL_CLOSE 0
#define XNAP_FAIL_OPEN  1

/* modes */
#define XNAP_MODE_BLOCKING 0
#define XNAP_MODE_ASYNC    1

extern ngx_module_t ngx_http_xngin_module;

/* ---------- codec ---------- */

typedef struct {
    u_char      *start;
    u_char      *pos;
    u_char      *end;
    ngx_pool_t  *pool;
} ngx_xnap_wbuf_t;

typedef struct {
    u_char  *pos;
    u_char  *end;
    unsigned err:1;
} ngx_xnap_rbuf_t;

typedef struct {
    u_char       type;
    int64_t      i;
    uint64_t     u;
    ngx_str_t    s;                 /* STR/BIN/IPV4/IPV6 bytes */
    u_char      *sub;               /* KVL / STRLIST raw payload */
    size_t       sub_len;
} ngx_xnap_val_t;

void       ngx_xnap_wbuf_init(ngx_xnap_wbuf_t *wb, ngx_pool_t *pool, size_t cap);
ngx_int_t  ngx_xnap_wbuf_u8(ngx_xnap_wbuf_t *wb, u_char b);
ngx_int_t  ngx_xnap_wbuf_bytes(ngx_xnap_wbuf_t *wb, const void *p, size_t n);
ngx_int_t  ngx_xnap_wbuf_varint(ngx_xnap_wbuf_t *wb, uint64_t v);
ngx_int_t  ngx_xnap_wbuf_svarint(ngx_xnap_wbuf_t *wb, int64_t v);
ngx_int_t  ngx_xnap_wbuf_kv_name(ngx_xnap_wbuf_t *wb, const char *name);
ngx_int_t  ngx_xnap_wbuf_kv_str(ngx_xnap_wbuf_t *wb, const char *name,
            const void *val, size_t len);
ngx_int_t  ngx_xnap_wbuf_kv_uint(ngx_xnap_wbuf_t *wb, const char *name,
            uint64_t v);
ngx_int_t  ngx_xnap_wbuf_kv_int(ngx_xnap_wbuf_t *wb, const char *name,
            int64_t v);
ngx_int_t  ngx_xnap_wbuf_kv_bool(ngx_xnap_wbuf_t *wb, const char *name,
            unsigned v);
ngx_int_t  ngx_xnap_wbuf_kv_ip(ngx_xnap_wbuf_t *wb, const char *name,
            struct sockaddr *sa);

uint64_t   ngx_xnap_rbuf_varint(ngx_xnap_rbuf_t *rb);
int64_t    ngx_xnap_rbuf_svarint(ngx_xnap_rbuf_t *rb);
ngx_int_t  ngx_xnap_rbuf_val(ngx_xnap_rbuf_t *rb, ngx_xnap_val_t *v);
ngx_int_t  ngx_xnap_rbuf_kv(ngx_xnap_rbuf_t *rb, ngx_str_t *name,
            ngx_xnap_val_t *v);
ngx_int_t  ngx_xnap_rbuf_strlist_next(ngx_xnap_rbuf_t *rb, ngx_str_t *s);

size_t     ngx_xnap_varint_len(uint64_t v);

/* ---------- structures ---------- */

typedef struct ngx_http_xngin_ctx_s   ngx_http_xngin_ctx_t;
typedef struct ngx_http_xngin_conn_s  ngx_http_xngin_conn_t;
typedef struct ngx_http_xngin_agent_s ngx_http_xngin_agent_t;
typedef struct ngx_http_xngin_group_s ngx_http_xngin_group_t;

typedef struct ngx_xnap_pkt_s {
    struct ngx_xnap_pkt_s *next;
    u_char                *pos;
    u_char                *last;
    u_char                 data[];
} ngx_xnap_pkt_t;

typedef struct {
    uint64_t              id;
    ngx_http_xngin_ctx_t *ctx;
} ngx_xnap_stream_t;

struct ngx_http_xngin_conn_s {
    ngx_peer_connection_t   pc;
    ngx_http_xngin_agent_t *agent;
    ngx_http_xngin_conn_t  *next;

    ngx_event_t            *timer;      /* ping / reconnect timer */

    ngx_xnap_stream_t      *streams;
    ngx_uint_t              streams_cap;
    ngx_uint_t              nstreams;
    uint64_t                next_sid;   /* odd ids */
    ngx_uint_t              max_streams;
    size_t                  max_frame;
    uint32_t                agent_caps;

    ngx_xnap_pkt_t         *out;
    ngx_xnap_pkt_t        **out_tail;

    u_char                 *rbuf;
    u_char                 *rpos;
    u_char                 *rlast;

    ngx_msec_t              ping_sent_at;
    ngx_msec_t              last_rtt;
    ngx_uint_t              missed_pongs;

    unsigned                ready:1;
    unsigned                hello_sent:1;
    unsigned                down:1;
};

struct ngx_http_xngin_agent_s {
    ngx_str_t                url_text;
    ngx_addr_t               addr;
    ngx_uint_t               weight;
    ngx_uint_t               max_streams;
    ngx_http_xngin_group_t  *group;
    ngx_http_xngin_conn_t   *conns;
};

struct ngx_http_xngin_group_s {
    ngx_str_t                name;
    ngx_array_t              agents;      /* ngx_http_xngin_agent_t */
    ngx_uint_t               keepalive;
    ngx_msec_t               ping_interval;
    ngx_uint_t               max_streams;
};

typedef struct {
    ngx_str_t                name;
    ngx_str_t                value;
} ngx_http_xngin_var_t;

struct ngx_http_xngin_ctx_s {
    ngx_http_request_t       *r;
    ngx_http_xngin_conn_t    *conn;
    uint64_t                  stream_id;
    uint64_t                  frame_id;
    ngx_event_t              *timer;

    ngx_int_t                 status;     /* rc returned when resumed */
    ngx_uint_t                state;

    unsigned                  async:1;
    unsigned                  body_wait:1;
    unsigned                  body_read:1;
    unsigned                  in_handler:1;
    unsigned                  retried:1;
    unsigned                  dispatched:1;

    ngx_msec_t                sent_at;
    ngx_msec_t                agent_rtt;
    ngx_flag_t                cache_status;

    ngx_str_t                 action;     /* allow/deny/redirect string */
    int64_t                   score;
    ngx_str_t                 reason;
    ngx_str_t                 error;      /* "", timeout, down, proto */
    ngx_array_t              *vars;       /* ngx_http_xngin_var_t */
    ngx_int_t                 deny_status;
    ngx_str_t                 deny_body;
    ngx_str_t                 deny_ctype;
    ngx_str_t                 cache_key_val; /* computed engine key */
    uint32_t                  cache_ttl;

    ngx_str_t                 request_id; /* shared NOTIFY correlation id */

    /* verdict-time mutations */
    ngx_str_t                 req_body;
    ngx_str_t                 res_body;
    ngx_array_t              *res_hdr_set;   /* ngx_http_xngin_var_t */
    ngx_array_t              *res_hdr_unset; /* ngx_str_t */

    unsigned                  req_body_set:1;
    unsigned                  res_body_set:1;
    unsigned                  res_done:1;    /* replacement body emitted */

    /* http-response round-trip (see ngx_http_xngin_resp.c) */
    unsigned                  is_resp:1;     /* this ctx is a resp stream */
    unsigned                  resp_hold:1;   /* headers held for verdict */
    unsigned                  resp_pass:1;   /* cap exceeded: passthrough */
    unsigned                  resp_sent:1;   /* output released */
    ngx_http_xngin_ctx_t     *parent;        /* req ctx, when is_resp */
    ngx_http_xngin_ctx_t     *resp_ctx;      /* resp ctx, when !is_resp */
    ngx_chain_t              *resp_held;
    ngx_chain_t             **resp_held_tail;
    size_t                    resp_held_len;
};

typedef struct {
    ngx_array_t              *groups;     /* ngx_http_xngin_group_t */
    ngx_shm_zone_t           *cache_zone;
} ngx_http_xngin_main_conf_t;

typedef struct {
    ngx_flag_t                tls_inspect;
    ngx_array_t              *tls_deny;   /* ngx_str_t, JA4 fingerprints */
} ngx_http_xngin_srv_conf_t;

typedef struct {
    ngx_str_t                 ch_raw;    /* raw ClientHello handshake msg */
    ngx_str_t                 ja4;       /* 36-char JA4 fingerprint */
    ngx_str_t                 ja4_raw;   /* unhashed JA4_r, debugging */
} ngx_http_xngin_hello_t;

typedef struct {
    ngx_flag_t                enable;
    ngx_str_t                 group_name;
    ngx_http_xngin_group_t   *group;
    ngx_uint_t                mode;
    ngx_msec_t                timeout;
    ngx_uint_t                fail;
    ngx_flag_t                body_inspect;
    size_t                    body_max;
    ngx_flag_t                response;
    size_t                    res_body_max;
    ngx_http_complex_value_t *cache_key;   /* engine-side cache key tpl */
} ngx_http_xngin_loc_conf_t;

typedef struct {
    ngx_rbtree_t              rbtree;
    ngx_rbtree_node_t         sentinel;
    ngx_queue_t               queue;
    ngx_uint_t                nhit;
    ngx_uint_t                nmiss;
} ngx_http_xngin_cache_shctx_t;

/* ---------- conn layer ---------- */

ngx_int_t   ngx_http_xngin_conn_init_worker(ngx_http_xngin_main_conf_t *mmcf,
                ngx_cycle_t *cycle);
void        ngx_http_xngin_conn_free_worker(ngx_http_xngin_main_conf_t *mmcf,
                ngx_cycle_t *cycle);
ngx_http_xngin_conn_t *ngx_http_xngin_conn_pick(ngx_http_xngin_group_t *g);
ngx_http_xngin_conn_t *ngx_http_xngin_conn_pick_caps(
                ngx_http_xngin_group_t *g, uint32_t caps);
ngx_int_t   ngx_http_xngin_conn_send(ngx_http_xngin_conn_t *c, u_char type,
                uint32_t flags, uint64_t sid, uint64_t fid,
                u_char *payload, size_t len);
void        ngx_http_xngin_stream_add(ngx_http_xngin_conn_t *c, uint64_t sid,
                ngx_http_xngin_ctx_t *ctx);
ngx_http_xngin_ctx_t *ngx_http_xngin_stream_find(ngx_http_xngin_conn_t *c,
                uint64_t sid);
void        ngx_http_xngin_stream_del(ngx_http_xngin_conn_t *c, uint64_t sid);

/* ---------- request layer ---------- */

ngx_int_t   ngx_http_xngin_dispatch(ngx_http_request_t *r,
                ngx_http_xngin_ctx_t *ctx);
void        ngx_http_xngin_ctx_abort(ngx_http_xngin_ctx_t *ctx);
void        ngx_http_xngin_timeout(ngx_event_t *ev);
ngx_int_t   ngx_http_xngin_verdict(ngx_http_xngin_conn_t *c,
                ngx_http_xngin_ctx_t *ctx, u_char *payload, size_t len);
ngx_int_t   ngx_http_xngin_build_notify(ngx_http_request_t *r,
                ngx_http_xngin_ctx_t *ctx, ngx_xnap_wbuf_t *wb);
ngx_int_t   ngx_http_xngin_send_body(ngx_http_request_t *r,
                ngx_http_xngin_ctx_t *ctx);
void        ngx_http_xngin_parse_vars(ngx_http_request_t *r,
                ngx_http_xngin_ctx_t *ctx, u_char *data, size_t len);
void        ngx_http_xngin_parse_res_hdr_set(ngx_http_request_t *r,
                ngx_http_xngin_ctx_t *ctx, u_char *data, size_t len);
void        ngx_http_xngin_parse_res_hdr_unset(ngx_http_request_t *r,
                ngx_http_xngin_ctx_t *ctx, u_char *data, size_t len,
                uint64_t count);

/* ---------- response layer ---------- */

void        ngx_http_xngin_filters_init(void);
ngx_int_t   ngx_http_xngin_res_hdr_apply(ngx_http_request_t *r,
                ngx_http_xngin_ctx_t *ctx);
ngx_int_t   ngx_http_xngin_header_filter(ngx_http_request_t *r);
ngx_int_t   ngx_http_xngin_body_filter(ngx_http_request_t *r,
                ngx_chain_t *in);
ngx_int_t   ngx_http_xngin_resp_verdict(ngx_http_xngin_conn_t *c,
                ngx_http_xngin_ctx_t *ctx, u_char *payload, size_t len);
void        ngx_http_xngin_resp_conn_failed(ngx_http_xngin_ctx_t *ctx);
void        ngx_http_xngin_resp_release(ngx_http_xngin_ctx_t *ctx,
                ngx_chain_t *body);
void        ngx_http_xngin_resp_abort(ngx_http_xngin_ctx_t *ctx);

/* ---------- tls ---------- */

ngx_int_t   ngx_http_xngin_tls_init(ngx_conf_t *cf);
ngx_http_xngin_hello_t *ngx_http_xngin_tls_hello(ngx_connection_t *c);

/* ---------- cache ---------- */

ngx_int_t   ngx_http_xngin_cache_lookup(ngx_http_request_t *r,
                ngx_http_xngin_ctx_t *ctx, ngx_str_t *key,
                ngx_int_t *out_status, int64_t *out_score,
                ngx_str_t *out_reason);
void        ngx_http_xngin_cache_store(ngx_http_request_t *r,
                ngx_http_xngin_ctx_t *ctx, ngx_str_t *key, uint32_t ttl);
ngx_int_t   ngx_http_xngin_cache_zone_init(ngx_shm_zone_t *shm_zone,
                void *data);

/* ---------- module glue ---------- */

extern ngx_str_t ngx_http_xngin_uri_arg_sep;
void ngx_http_xngin_resume(ngx_http_request_t *r, ngx_int_t status);

#endif /* _NGX_HTTP_XNGIN_MODULE_H_INCLUDED_ */
