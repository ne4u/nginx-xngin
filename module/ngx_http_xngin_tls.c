#include "ngx_http_xngin_module.h"

#if (NGX_SSL) && defined(SSL_CLIENT_HELLO_SUCCESS)

#include <ngx_event_openssl.h>
#include <ngx_http_ssl_module.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <ctype.h>


#define XNAP_CH_CAP  16384

/*
 * nginx >= 1.29.2 installs ngx_ssl_client_hello_callback() as the ctx
 * client_hello_cb and keeps the real work behind an ngx_ssl_client_hello_arg
 * { servername } stored at ngx_ssl_client_hello_arg_index in ctx ex_data.
 * We hook *that* extension point: replace the stored arg with ours whose
 * first member is layout-compatible, so nginx keeps its cb slot and SNI
 * validation, then calls our function which chains to the saved arg.
 * On older nginx nothing occupied the cb slot, so a plain
 * SSL_CTX_set_client_hello_cb() is safe there.
 */
#if (nginx_version >= 1029002)
#define NGX_XNGIN_TLS_ARG  1
#endif


/* one entry per server block on the ctx owner's listen addrs: the
   ClientHello cb resolves the SNI to an entry, so a JA4 ban only
   binds the groups (and static deny list) of the server the client
   actually asked for */
typedef struct {
    ngx_http_core_srv_conf_t  *cscf;
    ngx_array_t               *deny;    /* ngx_str_t, JA4 fingerprints */
    ngx_array_t               *groups;  /* ngx_http_xngin_group_t* this
                                           server's locations can reach:
                                           scopes pushed JA4 bans */
} ngx_http_xngin_tls_srv_t;

typedef struct {
    ngx_array_t *servers;       /* ngx_http_xngin_tls_srv_t; elts[0] is
                                   the ctx owner's own (default) entry */
    unsigned     tls:1;         /* ctx owner asked xngin_tls_inspect */
    unsigned     h2:1;          /* ctx owner asked xngin_h2_inspect */
} ngx_http_xngin_tls_ctx_t;

#if (NGX_XNGIN_TLS_ARG)

typedef struct {
    ngx_ssl_servername_pt        servername;   /* MUST be first member */
    ngx_ssl_client_hello_arg    *saved;        /* previous arg to chain */
    ngx_array_t                 *servers;  /* same scope as
                                              tctx->servers */
    unsigned                     tls:1;    /* ctx owner's inspect flags */
    unsigned                     h2:1;
} ngx_http_xngin_tls_arg_t;

#endif


static int  ngx_http_xngin_tls_ex_index = -1;

static void ngx_http_xngin_msg_cb(int write_p, int version,
    int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
static int  ngx_http_xngin_ch_cb(SSL *s, int *al, void *arg);
#if (NGX_XNGIN_TLS_ARG)
static int  ngx_http_xngin_ssl_servername(ngx_ssl_conn_t *s, int *ad,
    void *arg);
#endif
static ngx_http_xngin_hello_t *ngx_http_xngin_hello_new(ngx_connection_t *c,
    SSL *s);
static void ngx_http_xngin_ja4(SSL *s, ngx_connection_t *c,
    ngx_http_xngin_hello_t *h);
static ngx_int_t ngx_http_xngin_denied(ngx_http_xngin_hello_t *h,
    ngx_array_t *deny, ngx_array_t *groups);
static ngx_int_t ngx_http_xngin_hello_sni(SSL *s, ngx_str_t *host);
#if (NGX_QUIC)
static void ngx_http_xngin_quic_tp(ngx_connection_t *c,
    ngx_http_xngin_hello_t *h);
#endif
static ngx_http_xngin_tls_srv_t *ngx_http_xngin_tls_pick(
    ngx_connection_t *c, ngx_array_t *servers, ngx_str_t *sni);


ngx_http_xngin_hello_t *
ngx_http_xngin_tls_hello(ngx_connection_t *c)
{
    if (c->ssl == NULL || c->ssl->connection == NULL
        || ngx_http_xngin_tls_ex_index == -1)
    {
        return NULL;
    }

    return SSL_get_ex_data(c->ssl->connection, ngx_http_xngin_tls_ex_index);
}


static ngx_http_xngin_hello_t *
ngx_http_xngin_hello_new(ngx_connection_t *c, SSL *s)
{
    ngx_http_xngin_hello_t *h;

    if (ngx_http_xngin_tls_ex_index == -1) {
        return NULL;
    }

    h = SSL_get_ex_data(s, ngx_http_xngin_tls_ex_index);
    if (h) {
        return h;
    }

    h = ngx_pcalloc(c->pool, sizeof(ngx_http_xngin_hello_t));
    if (h == NULL) {
        return NULL;
    }

    SSL_set_ex_data(s, ngx_http_xngin_tls_ex_index, h);
    return h;
}


/* raw ClientHello capture: msg_callback sees full handshake messages
   (4-byte header included) before the state machine consumes them.
   The client's Finished is the earliest point where nginx has already
   assigned c->ssl->handler — swap it there to install the h2 recv tee */
static void
ngx_http_xngin_msg_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    const u_char           *p = buf;
    ngx_connection_t       *c;
    ngx_http_xngin_hello_t *h;

    if (write_p || content_type != SSL3_RT_HANDSHAKE || len == 0) {
        return;
    }

    if (p[0] == SSL3_MT_FINISHED) {
        c = ngx_ssl_get_connection(ssl);
        if (c == NULL) {
            return;
        }
        h = ngx_http_xngin_tls_hello(c);
        if (h != NULL && h->h2fp) {
            ngx_http_xngin_h2fp_ssl_hook(c);
        }
        return;
    }

    if (p[0] != SSL3_MT_CLIENT_HELLO || len > XNAP_CH_CAP) {
        return;
    }

    c = ngx_ssl_get_connection(ssl);
    if (c == NULL || c->pool == NULL) {
        return;
    }

    h = ngx_http_xngin_hello_new(c, ssl);
    if (h == NULL || h->ch_raw.data) {
        return;   /* keep the first ClientHello (HRR sends a second) */
    }

    h->ch_raw.data = ngx_pnalloc(c->pool, len);
    if (h->ch_raw.data == NULL) {
        return;
    }

    ngx_memcpy(h->ch_raw.data, buf, len);
    h->ch_raw.len = len;
}


static ngx_inline ngx_int_t
ngx_http_xngin_is_grease(uint16_t v)
{
    return ((v & 0x0f0f) == 0x0a0a) && ((v >> 8) == (v & 0xff));
}


static int
ngx_http_xngin_cmp_u16(const void *a, const void *b)
{
    uint16_t va = *(const uint16_t *) a;
    uint16_t vb = *(const uint16_t *) b;
    return (va > vb) - (va < vb);
}


static void
ngx_http_xngin_map_version(uint16_t ver, u_char out[2])
{
    switch (ver) {
        case 0x0304: out[0] = '1'; out[1] = '3'; break;
        case 0x0303: out[0] = '1'; out[1] = '2'; break;
        case 0x0302: out[0] = '1'; out[1] = '1'; break;
        case 0x0301: out[0] = '1'; out[1] = '0'; break;
        case 0x0300: out[0] = 's'; out[1] = '3'; break;
        case 0xfeff: out[0] = 'd'; out[1] = '1'; break;
        case 0xfefd: out[0] = 'd'; out[1] = '2'; break;
        case 0xfefc: out[0] = 'd'; out[1] = '3'; break;
        default:     out[0] = '0'; out[1] = '0'; break;
    }
}


static void
ngx_http_xngin_sha256_hex12(const u_char *data, size_t len, u_char out[13])
{
    static const char hex[] = "0123456789abcdef";
    u_char        digest[SHA256_DIGEST_LENGTH];
    unsigned int  dlen = SHA256_DIGEST_LENGTH;
    size_t        i;

    if (len == 0) {
        ngx_memcpy(out, "000000000000", 13);
        return;
    }

    EVP_Digest(data, len, digest, &dlen, EVP_sha256(), NULL);

    for (i = 0; i < 6; i++) {
        out[i * 2]     = (u_char) hex[(digest[i] >> 4) & 0x0f];
        out[i * 2 + 1] = (u_char) hex[digest[i] & 0x0f];
    }
    out[12] = '\0';
}


static void
ngx_http_xngin_ja4(SSL *s, ngx_connection_t *c, ngx_http_xngin_hello_t *h)
{
    const unsigned char *cipher_bytes = NULL;
    const unsigned char *ext_data = NULL;
    size_t               cipher_len = 0, ext_data_len = 0, i;
    int                 *ext_list = NULL;
    size_t               ext_len = 0;
    uint16_t             highest_ver = 0;
    u_char               sni_char = 'i';
    u_char               alpn_chars[2] = {'0', '0'};
    u_char               ver_chars[2];
    u_char               ja4_a[11], b_hash[13], c_hash[13];
    u_char               ja4_b_raw[256 * 5], ja4_c_raw[512 * 5 + 2];
    u_char              *p;
    size_t               b_len, c_len, raw_len;
    uint16_t             ciphers[256];
    size_t               cipher_count = 0;
    uint16_t             extensions[256];
    size_t               ext_total = 0, ext_filtered = 0;
    uint16_t             sig_algs[256];
    size_t               sig_count = 0;

    highest_ver = (uint16_t) SSL_client_hello_get0_legacy_version(s);

    cipher_len = SSL_client_hello_get0_ciphers(s, &cipher_bytes);
    for (i = 0; i + 1 < cipher_len && cipher_count < 256; i += 2) {
        uint16_t cs = ((uint16_t) cipher_bytes[i] << 8) | cipher_bytes[i + 1];
        if (!ngx_http_xngin_is_grease(cs)) {
            ciphers[cipher_count++] = cs;
        }
    }

    if (SSL_client_hello_get1_extensions_present(s, &ext_list, &ext_len) == 1) {
        for (i = 0; i < ext_len && ext_total < 256; i++) {
            uint16_t et = (uint16_t) ext_list[i];
            if (ngx_http_xngin_is_grease(et)) {
                continue;
            }
            ext_total++;

            /* SNI and ALPN count toward JA4_a but are excluded from JA4_c */
            if (et != TLSEXT_TYPE_server_name
                && et != TLSEXT_TYPE_application_layer_protocol_negotiation)
            {
                extensions[ext_filtered++] = et;
            }
        }
        OPENSSL_free(ext_list);
    }

    if (SSL_client_hello_get0_ext(s, TLSEXT_TYPE_server_name, &ext_data,
                                  &ext_data_len) == 1
        && ext_data_len > 0)
    {
        sni_char = 'd';
    }

    if (SSL_client_hello_get0_ext(s, TLSEXT_TYPE_supported_versions,
                                  &ext_data, &ext_data_len) == 1
        && ext_data_len >= 3)
    {
        size_t   list_len = ext_data[0];
        uint16_t max_v = 0;

        for (i = 1; i + 1 < ext_data_len && i < 1 + list_len; i += 2) {
            uint16_t v = ((uint16_t) ext_data[i] << 8) | ext_data[i + 1];
            if (!ngx_http_xngin_is_grease(v) && v > max_v) {
                max_v = v;
            }
        }
        if (max_v > 0) {
            highest_ver = max_v;
        }
    }

    if (SSL_client_hello_get0_ext(s,
            TLSEXT_TYPE_application_layer_protocol_negotiation,
            &ext_data, &ext_data_len) == 1
        && ext_data_len >= 3)
    {
        size_t list_len = ((size_t) ext_data[0] << 8) | ext_data[1];
        size_t pos = 2;

        while (pos < ext_data_len && pos < 2 + list_len) {
            size_t proto_len = ext_data[pos++];

            if (proto_len > 0 && pos + proto_len <= ext_data_len) {
                if (proto_len == 2) {
                    uint16_t g = ((uint16_t) ext_data[pos] << 8)
                                 | ext_data[pos + 1];
                    if (ngx_http_xngin_is_grease(g)) {
                        pos += proto_len;
                        continue;
                    }
                }

                {
                    u_char first = ext_data[pos];
                    u_char last  = ext_data[pos + proto_len - 1];

                    if (isalnum(first) && isalnum(last)) {
                        alpn_chars[0] = first;
                        alpn_chars[1] = last;
                    } else {
                        static const char hex[] = "0123456789abcdef";
                        alpn_chars[0] = (u_char) hex[(first >> 4) & 0x0f];
                        alpn_chars[1] = (u_char) hex[last & 0x0f];
                    }
                }
                break;
            }
            pos += proto_len;
        }
    }

    if (SSL_client_hello_get0_ext(s, TLSEXT_TYPE_signature_algorithms,
                                  &ext_data, &ext_data_len) == 1
        && ext_data_len >= 2)
    {
        size_t list_len = ((size_t) ext_data[0] << 8) | ext_data[1];

        for (i = 2; i + 1 < ext_data_len && i < 2 + list_len
                    && sig_count < 256; i += 2)
        {
            uint16_t sa = ((uint16_t) ext_data[i] << 8) | ext_data[i + 1];
            if (!ngx_http_xngin_is_grease(sa)) {
                sig_algs[sig_count++] = sa;
            }
        }
    }

    if (cipher_count > 1) {
        qsort(ciphers, cipher_count, sizeof(uint16_t),
              ngx_http_xngin_cmp_u16);
    }
    if (ext_filtered > 1) {
        qsort(extensions, ext_filtered, sizeof(uint16_t),
              ngx_http_xngin_cmp_u16);
    }

    ngx_http_xngin_map_version(highest_ver, ver_chars);

    {
        u_char tchar = 't';

#if (NGX_QUIC)
        if (c->listening != NULL && c->listening->quic) {
            tchar = 'q';
        }
#endif

        ngx_snprintf(ja4_a, sizeof(ja4_a) - 1, "%c%c%c%c%02ui%02ui%c%c",
                     tchar,
                     ver_chars[0], ver_chars[1], sni_char,
                     (ngx_uint_t) (cipher_count > 99 ? 99 : cipher_count),
                     (ngx_uint_t) (ext_total > 99 ? 99 : ext_total),
                     alpn_chars[0], alpn_chars[1]);
        ja4_a[10] = '\0';
    }

    p = ja4_b_raw;
    for (i = 0; i < cipher_count; i++) {
        if (i) {
            *p++ = ',';
        }
        p = ngx_snprintf(p, 5, "%04xd", ciphers[i]);
    }
    b_len = p - ja4_b_raw;

    p = ja4_c_raw;
    for (i = 0; i < ext_filtered; i++) {
        if (i) {
            *p++ = ',';
        }
        p = ngx_snprintf(p, 5, "%04xd", extensions[i]);
    }
    if (sig_count) {
        if (ext_filtered) {
            *p++ = '_';
        }
        for (i = 0; i < sig_count; i++) {
            if (i) {
                *p++ = ',';
            }
            p = ngx_snprintf(p, 5, "%04xd", sig_algs[i]);
        }
    }
    c_len = p - ja4_c_raw;

    ngx_http_xngin_sha256_hex12(ja4_b_raw, b_len, b_hash);
    ngx_http_xngin_sha256_hex12(ja4_c_raw, c_len, c_hash);

    h->ja4.data = ngx_pnalloc(c->pool, 37);
    if (h->ja4.data) {
        h->ja4.len = ngx_snprintf(h->ja4.data, 37, "%s_%s_%s",
                                  ja4_a, b_hash, c_hash) - h->ja4.data;
        h->ja4.data[h->ja4.len] = '\0';
    }

    raw_len = 10 + 1 + b_len + 1 + c_len;
    h->ja4_raw.data = ngx_pnalloc(c->pool, raw_len + 1);
    if (h->ja4_raw.data) {
        p = h->ja4_raw.data;
        p = ngx_cpymem(p, ja4_a, 10);
        *p++ = '_';
        p = ngx_cpymem(p, ja4_b_raw, b_len);
        *p++ = '_';
        p = ngx_cpymem(p, ja4_c_raw, c_len);
        *p = '\0';
        h->ja4_raw.len = raw_len;
    }
}


#if (NGX_QUIC)
/* QUIC transport parameters live in TLS extension 0x0039 inside the
   captured ClientHello: extract the raw ext body + ordered param-id
   list.  Wire params are {varint id, varint len, value} tuples */
static void
ngx_http_xngin_quic_tp(ngx_connection_t *c, ngx_http_xngin_hello_t *h)
{
    u_char   *p, *end, *e;
    size_t    n, cap;
    uint64_t  v;

    if (h->quic_tp.data || h->ch_raw.len < 4 + 2 + 32 + 1) {
        return;
    }

    p = h->ch_raw.data + 4;
    end = h->ch_raw.data + h->ch_raw.len;

    p += 2 + 32;                                /* version + random */
    if (p >= end || p + 1 + p[0] > end) { return; }
    p += 1 + p[0];                              /* session id */
    if (p + 2 > end) { return; }
    n = ((size_t) p[0] << 8) | p[1];
    if (p + 2 + n + 1 > end) { return; }
    p += 2 + n + 1 + p[2 + n];                  /* ciphers + comp */
    if (p + 2 > end) { return; }
    n = ((size_t) p[0] << 8) | p[1];
    p += 2;
    if (p + n > end) { return; }
    e = p + n;                                  /* extensions range */

    while (p + 4 <= e) {
        uint16_t  et = ((uint16_t) p[0] << 8) | p[1];
        n = ((size_t) p[2] << 8) | p[3];
        p += 4;
        if (p + n > e) { return; }
        if (et == 0x0039) {
            goto found;
        }
        p += n;
    }
    return;

found:
    h->quic_tp.data = ngx_pnalloc(c->pool, n);
    if (h->quic_tp.data == NULL) {
        return;
    }
    ngx_memcpy(h->quic_tp.data, p, n);
    h->quic_tp.len = n;

    /* ordered id list, decimal */
    cap = n * 6 + 1;
    h->quic_tps.data = ngx_pnalloc(c->pool, cap);
    if (h->quic_tps.data == NULL) {
        return;
    }

    e = p + n;
    while (p < e) {
        uint64_t  id;
        u_char   *w;

        id = ngx_http_xngin_qvarint(&p, e);
        if (id == (uint64_t) -1) {
            break;
        }
        v = ngx_http_xngin_qvarint(&p, e);
        if (v == (uint64_t) -1 || (uint64_t) (e - p) < v) {
            break;
        }
        p += v;

        w = h->quic_tps.data + h->quic_tps.len;
        if (h->quic_tps.len) {
            *w++ = ',';
        }
        h->quic_tps.len = ngx_snprintf(w, cap - (w - h->quic_tps.data),
                                       "%uL", id) - h->quic_tps.data;
    }
}
#endif /* NGX_QUIC */


/* pull the SNI hostname out of the ClientHello — same wire decode as
   ngx_ssl_client_hello_callback() */
static ngx_int_t
ngx_http_xngin_hello_sni(SSL *s, ngx_str_t *host)
{
    const unsigned char *p = NULL;
    size_t               len = 0;

    if (SSL_client_hello_get0_ext(s, TLSEXT_TYPE_server_name, &p, &len)
            != 1
        || len < 5
        || (size_t) (p[0] << 8) + p[1] + 2 != len
        || p[2] != TLSEXT_NAMETYPE_host_name
        || (size_t) (p[3] << 8) + p[4] + 2 + 3 != len)
    {
        return NGX_DECLINED;
    }

    host->len = len - 5;
    host->data = (u_char *) p + 5;

    if (host->len == 0 || host->len > TLSEXT_MAXLEN_host_name
        || ngx_strlchr(host->data, host->data + host->len, '\0'))
    {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


/* the ClientHello cb runs on the default server's ctx pre-SNI: resolve
   the name to a server ourselves so a ban only binds that server's
   groups.  This mirrors ngx_http_find_virtual_server() — static inside
   ngx_http_request.c, so not linkable — walking the same virtual_names
   in the same order: combined hash (exact + wildcard), then regexes. */
static ngx_http_core_srv_conf_t *
ngx_http_xngin_find_vserver(ngx_connection_t *c, ngx_str_t *host)
{
    ngx_http_connection_t     *hc;
    ngx_http_virtual_names_t  *vn;
    ngx_http_core_srv_conf_t  *cscf;
#if (NGX_PCRE)
    ngx_http_server_name_t    *sn;
    ngx_int_t                  n;
    ngx_uint_t                 i;
#endif

    hc = c->data;
    if (hc == NULL || hc->addr_conf == NULL) {
        return NULL;
    }

    vn = hc->addr_conf->virtual_names;
    if (vn == NULL) {
        return NULL;
    }

    cscf = ngx_hash_find_combined(&vn->names,
                                  ngx_hash_key(host->data, host->len),
                                  host->data, host->len);
    if (cscf) {
        return cscf;
    }

#if (NGX_PCRE)
    if (host->len && vn->nregex) {
        sn = vn->regex;
        for (i = 0; i < vn->nregex; i++) {
            n = ngx_regex_exec(sn[i].regex->regex, host, NULL, 0);
            if (n == NGX_REGEX_NO_MATCHED) {
                continue;
            }
            if (n >= 0) {
                return sn[i].server;
            }
            /* regex exec error: nginx's own servername pass will fail
               the handshake — fall through to the default server */
            return NULL;
        }
    }
#endif

    return NULL;
}


/* map the hello's SNI to the per-server entry collected at config
   time; no SNI, an unusable name, or no match selects the default
   server — elts[0] */
static ngx_http_xngin_tls_srv_t *
ngx_http_xngin_tls_pick(ngx_connection_t *c, ngx_array_t *servers,
    ngx_str_t *sni)
{
    ngx_http_xngin_tls_srv_t  *ts = servers->elts;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_str_t                  host;
    ngx_uint_t                 i;

    if (sni != NULL && sni->len != 0 && sni->data != NULL) {
        host = *sni;

        /* validate + lowercase exactly like ngx_http_ssl_servername
           does before its own virtual-server match */
        if (ngx_http_validate_host(&host, NULL, c->pool, 1) == NGX_OK
            && host.len != 0)
        {
            cscf = ngx_http_xngin_find_vserver(c, &host);
            if (cscf) {
                for (i = 0; i < servers->nelts; i++) {
                    if (ts[i].cscf == cscf) {
                        return &ts[i];
                    }
                }
            }
        }
    }

    return &ts[0];
}


static ngx_int_t
ngx_http_xngin_denied(ngx_http_xngin_hello_t *h, ngx_array_t *deny,
    ngx_array_t *groups)
{
    ngx_str_t                   *d;
    ngx_uint_t                   i;
    ngx_http_xngin_main_conf_t  *mmcf;

    if (h == NULL || h->ja4.len == 0) {
        return 0;
    }

    /* agent-pushed JA4 bans bind the groups this server's locations
       actually use — a foreign group's push must not abort unrelated
       handshakes; the check stays local + synchronous */
    mmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_xngin_module);
    if (mmcf && groups && groups->nelts
        && ngx_http_xngin_ban_check(mmcf, XNAP_BAN_JA4, &h->ja4, groups))
    {
        return 1;
    }

    if (deny == NULL) {
        return 0;
    }

    d = deny->elts;
    for (i = 0; i < deny->nelts; i++) {
        if (d[i].len == h->ja4.len
            && ngx_strncasecmp(d[i].data, h->ja4.data, h->ja4.len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


#if (NGX_XNGIN_TLS_ARG)

/*
 * servername hook on nginx >= 1.29.2: invoked from inside nginx's
 * ngx_ssl_client_hello_callback (arg slot), so the parsed host arrives
 * in arg and the SSL_client_hello_* accessors are still valid here.
 */
static int
ngx_http_xngin_ssl_servername(ngx_ssl_conn_t *s, int *ad, void *arg)
{
    ngx_connection_t          *c;
    ngx_http_xngin_tls_arg_t  *targ = NULL;
    ngx_http_xngin_tls_srv_t  *ts;
    ngx_http_xngin_hello_t    *h = NULL;
    ngx_str_t                 sni, *sp;

    c = ngx_ssl_get_connection(s);
    if (c != NULL && c->pool != NULL) {
        targ = SSL_CTX_get_ex_data(c->ssl->session_ctx,
                                   ngx_ssl_client_hello_arg_index);

        h = ngx_http_xngin_hello_new(c, s);
        if (h != NULL && h->ja4.data == NULL) {
            ngx_http_xngin_ja4(s, c, h);
        }
    }

    if (targ && c != NULL && c->pool != NULL) {
        /* arg is the ngx_str_t host nginx already parsed out of the
           hello (NULL on BoringSSL's select-certificate path — decode
           the extension ourselves there) */
        sp = arg;
        if (sp == NULL
            && ngx_http_xngin_hello_sni(s, &sni) == NGX_OK)
        {
            sp = &sni;
        }

        ts = ngx_http_xngin_tls_pick(c, targ->servers, sp);
        if (h != NULL) {
            h->tlsfp = targ->tls;
            h->h2fp = targ->h2;
#if (NGX_QUIC)
            if (c->listening != NULL && c->listening->quic
                && h->ch_raw.data)
            {
                ngx_http_xngin_quic_tp(c, h);
            }
#endif
        }
        if (ngx_http_xngin_denied(h, ts->deny, ts->groups)) {
            *ad = SSL_AD_ILLEGAL_PARAMETER;
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }

    if (targ && targ->saved && targ->saved->servername) {
        return targ->saved->servername(s, ad, arg);
    }

    return SSL_TLSEXT_ERR_OK;
}

#endif /* NGX_XNGIN_TLS_ARG */


/* client_hello_cb path for nginx < 1.29.2: nothing else uses the slot */
static int
ngx_http_xngin_ch_cb(SSL *s, int *al, void *arg)
{
    ngx_http_xngin_tls_ctx_t *tctx = arg;
    ngx_http_xngin_tls_srv_t *ts;
    ngx_connection_t         *c;
    ngx_http_xngin_hello_t   *h = NULL;
    ngx_str_t                 sni, *sp = NULL;

    c = ngx_ssl_get_connection(s);

    if (c != NULL && c->pool != NULL) {
        h = ngx_http_xngin_hello_new(c, s);

        if (h != NULL && h->ja4.data == NULL) {
            ngx_http_xngin_ja4(s, c, h);
        }

        if (ngx_http_xngin_hello_sni(s, &sni) == NGX_OK) {
            sp = &sni;
        }

        ts = ngx_http_xngin_tls_pick(c, tctx->servers, sp);
        if (h != NULL) {
            h->tlsfp = tctx->tls;
            h->h2fp = tctx->h2;
#if (NGX_QUIC)
            if (c->listening != NULL && c->listening->quic
                && h->ch_raw.data)
            {
                ngx_http_xngin_quic_tp(c, h);
            }
#endif
        }
        if (ngx_http_xngin_denied(h, ts->deny, ts->groups)) {
            *al = SSL_AD_ILLEGAL_PARAMETER;
            return SSL_CLIENT_HELLO_ERROR;
        }
    }

#if (NGX_XNGIN_TLS_ARG)
    /* unreachable in practice: the arg path is installed instead;
       kept for the saved==NULL fallback so nginx's SNI still runs */
    return ngx_ssl_client_hello_callback(s, al, NULL);
#else
    return SSL_CLIENT_HELLO_SUCCESS;
#endif
}


/* every group this location's step chain can reach → server's ban scope;
   recurses into the location sets it owns (runs in postconfiguration,
   after ngx_http_init_locations split the sets) */
static void
ngx_http_xngin_tls_collect_one(ngx_conf_t *cf, ngx_array_t *groups,
    ngx_http_core_loc_conf_t *clcf);

static void
ngx_http_xngin_tls_collect_tree(ngx_conf_t *cf, ngx_array_t *groups,
    ngx_http_location_tree_node_t *node)
{
    if (node == NULL) {
        return;
    }

    ngx_http_xngin_tls_collect_one(cf, groups, node->exact);
    ngx_http_xngin_tls_collect_one(cf, groups, node->inclusive);

    ngx_http_xngin_tls_collect_tree(cf, groups, node->left);
    ngx_http_xngin_tls_collect_tree(cf, groups, node->right);
    ngx_http_xngin_tls_collect_tree(cf, groups, node->tree);
}


static void
ngx_http_xngin_tls_collect_lcf(ngx_array_t *groups,
    ngx_http_xngin_loc_conf_t *lcf)
{
    ngx_http_xngin_group_t  **gp, **np, **elts;
    ngx_uint_t                i, j;

    if (lcf == NULL || lcf->groups == NULL) {
        return;
    }

    gp = lcf->groups->elts;
    elts = groups->elts;
    for (i = 0; i < lcf->groups->nelts; i++) {
        for (j = 0; j < groups->nelts; j++) {
            if (elts[j] == gp[i]) {
                break;
            }
        }
        if (j == groups->nelts) {
            np = ngx_array_push(groups);
            if (np) {
                *np = gp[i];
                elts = groups->elts;
            }
        }
    }
}


static void
ngx_http_xngin_tls_collect_one(ngx_conf_t *cf, ngx_array_t *groups,
    ngx_http_core_loc_conf_t *clcf)
{
    ngx_http_core_loc_conf_t  **clcfp;

    /* the server-level core loc conf has loc_conf == NULL — nginx sets
       the back-pointer only for location{} blocks */
    if (clcf == NULL || clcf->loc_conf == NULL) {
        return;
    }

    ngx_http_xngin_tls_collect_lcf(groups,
        clcf->loc_conf[ngx_http_xngin_module.ctx_index]);

    /* nested locations reachable through this one */
    ngx_http_xngin_tls_collect_tree(cf, groups, clcf->static_locations);

#if (NGX_PCRE)
    for (clcfp = clcf->regex_locations; clcfp && *clcfp; clcfp++) {
        ngx_http_xngin_tls_collect_one(cf, groups, *clcfp);
    }
#endif
    for (clcfp = clcf->predicate_locations; clcfp && *clcfp; clcfp++) {
        ngx_http_xngin_tls_collect_one(cf, groups, *clcfp);
    }
}


static void
ngx_http_xngin_tls_collect_server(ngx_conf_t *cf, ngx_array_t *groups,
    ngx_http_core_srv_conf_t *cscf)
{
    ngx_http_core_loc_conf_t  *pclcf, **clcfp;

    pclcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];

    /* server-level xngin loc conf (xngin_group written in server{}) —
       pclcf->loc_conf is NULL so index the ctx array directly */
    ngx_http_xngin_tls_collect_lcf(groups,
        cscf->ctx->loc_conf[ngx_http_xngin_module.ctx_index]);

    ngx_http_xngin_tls_collect_tree(cf, groups, pclcf->static_locations);

#if (NGX_PCRE)
    for (clcfp = pclcf->regex_locations; clcfp && *clcfp; clcfp++) {
        ngx_http_xngin_tls_collect_one(cf, groups, *clcfp);
    }
#endif
    for (clcfp = pclcf->predicate_locations; clcfp && *clcfp; clcfp++) {
        ngx_http_xngin_tls_collect_one(cf, groups, *clcfp);
    }
    for (clcfp = cscf->named_locations; clcfp && *clcfp; clcfp++) {
        ngx_http_xngin_tls_collect_one(cf, groups, *clcfp);
    }
}


/* one entry per server block (deduped by cscf): own tls_deny list +
   own group reach — the hello-time ban check binds only the server
   the client's SNI resolves to */
static ngx_int_t
ngx_http_xngin_tls_server_add(ngx_conf_t *cf, ngx_array_t *servers,
    ngx_http_core_srv_conf_t *cscf)
{
    ngx_http_xngin_tls_srv_t   *ts, *elts;
    ngx_http_xngin_srv_conf_t  *xscf;
    ngx_uint_t                  i;

    elts = servers->elts;
    for (i = 0; i < servers->nelts; i++) {
        if (elts[i].cscf == cscf) {
            return NGX_OK;
        }
    }

    ts = ngx_array_push(servers);
    if (ts == NULL) {
        return NGX_ERROR;
    }

    ts->cscf = cscf;

    xscf = cscf->ctx->srv_conf[ngx_http_xngin_module.ctx_index];
    ts->deny = (xscf != NULL) ? xscf->tls_deny : NULL;

    ts->groups = ngx_array_create(cf->pool, 4,
                                  sizeof(ngx_http_xngin_group_t *));
    if (ts->groups == NULL) {
        return NGX_ERROR;
    }

    ngx_http_xngin_tls_collect_server(cf, ts->groups, cscf);

    return NGX_OK;
}


/* the ClientHello cb runs on the default server's ctx per listen addr,
   pre-SNI — collect one entry for every server on the addrs where this
   server is default, so the cb can scope a ban to the server the SNI
   resolves to.  elts[0] is the owner's own entry: the no-SNI fallback */
static ngx_array_t *
ngx_http_xngin_tls_server_list(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_http_core_srv_conf_t *cscf)
{
    ngx_array_t                 *servers;
    ngx_http_conf_port_t        *port;
    ngx_http_conf_addr_t        *addr;
    ngx_http_core_srv_conf_t   **srv;
    ngx_uint_t                   p, a, i;

    servers = ngx_array_create(cf->pool, 4,
                               sizeof(ngx_http_xngin_tls_srv_t));
    if (servers == NULL) {
        return NULL;
    }

    if (ngx_http_xngin_tls_server_add(cf, servers, cscf) != NGX_OK) {
        return NULL;
    }

    if (cmcf->ports) {
        port = cmcf->ports->elts;
        for (p = 0; p < cmcf->ports->nelts; p++) {
            addr = port[p].addrs.elts;
            for (a = 0; a < port[p].addrs.nelts; a++) {
                if (addr[a].default_server != cscf) {
                    continue;
                }
                srv = addr[a].servers.elts;
                for (i = 0; i < addr[a].servers.nelts; i++) {
                    if (ngx_http_xngin_tls_server_add(cf, servers,
                                                      srv[i])
                        != NGX_OK)
                    {
                        return NULL;
                    }
                }
            }
        }
    }

    return servers;
}


ngx_int_t
ngx_http_xngin_tls_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_core_srv_conf_t  **cscfp;
    ngx_http_ssl_srv_conf_t    *sscf;
    ngx_http_xngin_srv_conf_t  *xscf;
    ngx_http_xngin_tls_ctx_t   *tctx;
    ngx_uint_t                  s;
#if (NGX_XNGIN_TLS_ARG)
    ngx_ssl_client_hello_arg   *saved;
    ngx_http_xngin_tls_arg_t   *targ;
#endif

    if (ngx_http_xngin_tls_ex_index == -1) {
        ngx_http_xngin_tls_ex_index =
            SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        if (ngx_http_xngin_tls_ex_index == -1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xngin: SSL_get_ex_new_index() failed");
            return NGX_ERROR;
        }
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        xscf = cscfp[s]->ctx->srv_conf[ngx_http_xngin_module.ctx_index];
        if (xscf == NULL || (!xscf->tls_inspect && !xscf->h2_inspect)) {
            continue;
        }

        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
        if (sscf == NULL || sscf->ssl.ctx == NULL) {
            continue;
        }

        SSL_CTX_set_msg_callback(sscf->ssl.ctx, ngx_http_xngin_msg_cb);

#if (NGX_XNGIN_TLS_ARG)

        saved = SSL_CTX_get_ex_data(sscf->ssl.ctx,
                                    ngx_ssl_client_hello_arg_index);
        if (saved == NULL) {
            goto raw_cb;
        }

        targ = ngx_pcalloc(cf->pool, sizeof(ngx_http_xngin_tls_arg_t));
        if (targ == NULL) {
            return NGX_ERROR;
        }

        targ->servername = ngx_http_xngin_ssl_servername;
        targ->saved = saved;
        targ->tls = (xscf->tls_inspect == 1);
        targ->h2 = (xscf->h2_inspect == 1);
        targ->servers = ngx_http_xngin_tls_server_list(cf, cmcf,
                                                       cscfp[s]);
        if (targ->servers == NULL) {
            return NGX_ERROR;
        }

        if (SSL_CTX_set_ex_data(sscf->ssl.ctx,
                                ngx_ssl_client_hello_arg_index, targ) == 0)
        {
            return NGX_ERROR;
        }

        continue;

raw_cb:

#endif
        {
            tctx = ngx_pcalloc(cf->pool,
                               sizeof(ngx_http_xngin_tls_ctx_t));
            if (tctx == NULL) {
                return NGX_ERROR;
            }

            tctx->tls = (xscf->tls_inspect == 1);
            tctx->h2 = (xscf->h2_inspect == 1);
            tctx->servers = ngx_http_xngin_tls_server_list(cf, cmcf,
                                                           cscfp[s]);
            if (tctx->servers == NULL) {
                return NGX_ERROR;
            }

            SSL_CTX_set_client_hello_cb(sscf->ssl.ctx,
                                        ngx_http_xngin_ch_cb, tctx);
        }
    }

    return NGX_OK;
}

#else /* !(NGX_SSL && SSL_CLIENT_HELLO_SUCCESS) */


ngx_int_t
ngx_http_xngin_tls_init(ngx_conf_t *cf)
{
    return NGX_OK;
}


ngx_http_xngin_hello_t *
ngx_http_xngin_tls_hello(ngx_connection_t *c)
{
    return NULL;
}


#endif /* NGX_SSL && SSL_CLIENT_HELLO_SUCCESS */
