#include "ngx_http_xngin_module.h"


/*
 * xngin_status content handler: JSON dump of this worker's agent
 * connections (per-worker view — each worker owns its own conns) plus
 * the shared verdict-cache counters from the shm zone.
 */

static size_t
ngx_http_xngin_status_bound(ngx_http_xngin_main_conf_t *mmcf)
{
    ngx_uint_t               i, j;
    ngx_http_xngin_group_t  *g;
    ngx_http_xngin_agent_t  *a;
    ngx_http_xngin_conn_t   *c;
    size_t                   n = 1024;

    if (mmcf->groups == NULL) {
        return n;
    }

    g = mmcf->groups->elts;
    for (i = 0; i < mmcf->groups->nelts; i++) {
        n += g[i].name.len + 32;
        a = g[i].agents.elts;
        for (j = 0; j < g[i].agents.nelts; j++) {
            n += a[j].url_text.len + 64;
            for (c = a[j].conns; c; c = c->next) {
                n += 160;
            }
        }
    }

    return n;
}


ngx_int_t
ngx_http_xngin_status_handler(ngx_http_request_t *r)
{
    ngx_http_xngin_main_conf_t   *mmcf;
    ngx_http_xngin_group_t       *g;
    ngx_http_xngin_agent_t       *a;
    ngx_http_xngin_conn_t        *c;
    ngx_http_xngin_cache_shctx_t *sh;
    ngx_slab_pool_t              *shpool;
    ngx_buf_t                    *b;
    ngx_chain_t                   out;
    ngx_int_t                     rc;
    ngx_uint_t                    i, j, gi, ci;
    u_char                       *p;
    size_t                        size;
    ngx_uint_t                    nhit = 0, nmiss = 0, nent = 0;

    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    mmcf = ngx_http_get_module_main_conf(r, ngx_http_xngin_module);

    if (mmcf->cache_zone) {
        sh = mmcf->cache_zone->data;
        if (sh) {
            shpool = (ngx_slab_pool_t *) mmcf->cache_zone->shm.addr;
            ngx_shmtx_lock(&shpool->mutex);
            nhit = sh->nhit;
            nmiss = sh->nmiss;
            nent = sh->nentries;
            ngx_shmtx_unlock(&shpool->mutex);
        }
    }

    size = ngx_http_xngin_status_bound(mmcf);

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->start = ngx_pnalloc(r->pool, size);
    if (b->start == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = b->start;
    b->end = b->start + size;
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    p = b->pos;
    p = ngx_cpymem(p, "{\"worker\":", sizeof("{\"worker\":") - 1);
    p = ngx_sprintf(p, "%P", ngx_pid);
    p = ngx_cpymem(p, ",\"groups\":[", sizeof(",\"groups\":[") - 1);

    gi = 0;
    if (mmcf->groups) {
        g = mmcf->groups->elts;
        for (i = 0; i < mmcf->groups->nelts; i++) {
            if (gi++) {
                *p++ = ',';
            }
            p = ngx_sprintf(p, "{\"name\":\"%V\",\"agents\":[",
                          &g[i].name);
            a = g[i].agents.elts;
            for (j = 0; j < g[i].agents.nelts; j++) {
                if (j) {
                    *p++ = ',';
                }
                p = ngx_sprintf(p, "{\"addr\":\"%V\",\"conns\":[",
                              &a[j].url_text);
                for (c = a[j].conns, ci = 0; c; c = c->next, ci++) {
                    if (ci) {
                        *p++ = ',';
                    }
                    p = ngx_sprintf(p,
                        "{\"ready\":%s,\"down\":%s,\"ssl\":%s,"
                        "\"streams\":%ui,\"max_streams\":%ui,"
                        "\"rtt_ms\":%M,\"missed_pongs\":%ui}",
                        c->ready ? "true" : "false",
                        c->down ? "true" : "false",
                        c->ssl ? "true" : "false",
                        c->nstreams, c->max_streams,
                        c->last_rtt, c->missed_pongs);
                }
                p = ngx_cpymem(p, "]}", sizeof("]}") - 1);
            }
            p = ngx_cpymem(p, "]}", sizeof("]}") - 1);
        }
    }

    p = ngx_sprintf(p, "],\"cache\":{\"enabled\":%s,\"hits\":%ui,"
                       "\"misses\":%ui,\"entries\":%ui}}",
                    mmcf->cache_zone ? "true" : "false",
                    nhit, nmiss, nent);

    b->last = p;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_len = sizeof("application/json") - 1;
    r->headers_out.content_type_lowcase = NULL;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}
