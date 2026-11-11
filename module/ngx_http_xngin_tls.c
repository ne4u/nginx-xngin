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


typedef struct {
    ngx_array_t *deny;          /* ngx_str_t, JA4 fingerprints */
} ngx_http_xngin_tls_ctx_t;

#if (NGX_XNGIN_TLS_ARG)

typedef struct {
    ngx_ssl_servername_pt        servername;   /* MUST be first member */
    ngx_ssl_client_hello_arg    *saved;        /* previous arg to chain */
    ngx_array_t                 *deny;
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
    ngx_array_t *deny);


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
   (4-byte header included) before the state machine consumes them */
static void
ngx_http_xngin_msg_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    const u_char           *p = buf;
    ngx_connection_t       *c;
    ngx_http_xngin_hello_t *h;

    if (write_p || content_type != SSL3_RT_HANDSHAKE || len == 0
        || p[0] != SSL3_MT_CLIENT_HELLO || len > XNAP_CH_CAP)
    {
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

    ngx_snprintf(ja4_a, sizeof(ja4_a) - 1, "t%c%c%c%02ui%02ui%c%c",
                 ver_chars[0], ver_chars[1], sni_char,
                 (ngx_uint_t) (cipher_count > 99 ? 99 : cipher_count),
                 (ngx_uint_t) (ext_total > 99 ? 99 : ext_total),
                 alpn_chars[0], alpn_chars[1]);
    ja4_a[10] = '\0';

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


static ngx_int_t
ngx_http_xngin_denied(ngx_http_xngin_hello_t *h, ngx_array_t *deny)
{
    ngx_str_t   *d;
    ngx_uint_t   i;

    if (h == NULL || h->ja4.len == 0 || deny == NULL) {
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
    ngx_http_xngin_hello_t    *h = NULL;

    c = ngx_ssl_get_connection(s);
    if (c != NULL && c->pool != NULL) {
        targ = SSL_CTX_get_ex_data(c->ssl->session_ctx,
                                   ngx_ssl_client_hello_arg_index);

        h = ngx_http_xngin_hello_new(c, s);
        if (h != NULL && h->ja4.data == NULL) {
            ngx_http_xngin_ja4(s, c, h);
        }
    }

    if (targ && ngx_http_xngin_denied(h, targ->deny)) {
        *ad = SSL_AD_ILLEGAL_PARAMETER;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
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
    ngx_connection_t         *c;
    ngx_http_xngin_hello_t   *h = NULL;

    c = ngx_ssl_get_connection(s);

    if (c != NULL && c->pool != NULL) {
        h = ngx_http_xngin_hello_new(c, s);

        if (h != NULL && h->ja4.data == NULL) {
            ngx_http_xngin_ja4(s, c, h);
        }
    }

    if (ngx_http_xngin_denied(h, tctx->deny)) {
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return SSL_CLIENT_HELLO_ERROR;
    }

#if (NGX_XNGIN_TLS_ARG)
    /* unreachable in practice: the arg path is installed instead;
       kept for the saved==NULL fallback so nginx's SNI still runs */
    return ngx_ssl_client_hello_callback(s, al, NULL);
#else
    return SSL_CLIENT_HELLO_SUCCESS;
#endif
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
        if (xscf == NULL || !xscf->tls_inspect) {
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
        targ->deny = xscf->tls_deny;

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

            tctx->deny = xscf->tls_deny;

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
