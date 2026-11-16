#include "ngx_http_xngin_module.h"


/* stored reason/body are clamped so one slab entry stays sane next to
   an 80KB-minimum zone; a larger payload simply isn't cached */
#define XNAP_CACHE_REASON_MAX  1024
#define XNAP_CACHE_BODY_MAX    (64 * 1024)
#define XNAP_CACHE_NODE_MAX    (80 * 1024)


/* node->data layout:
   [key      key_len]
   [group    group_len]   name of the group whose agent stored it;
                          scopes CONTROL cache-drop to the owner
   [reason   reason_len]
   [body     body_len]      deny body (0 for plain allows)
   [ctype    ctype_len]
   [hdrset   hdrset_len]    u16 count + count*(u16 nlen, name, u16 vlen, val)
   [hdrunset hdrunset_len]  u16 count + count*(u16 nlen, name) */
typedef struct {
    ngx_rbtree_node_t   node;
    ngx_queue_t         queue;
    uint64_t            key_h;
    time_t              expire;
    ngx_int_t           action;     /* NGX_DECLINED (allow) or HTTP status */
    int64_t             score;
    u_short             key_len;
    u_short             group_len;
    u_short             reason_len;
    uint32_t            body_len;
    u_short             ctype_len;
    uint32_t            hdrset_len;
    uint32_t            hdrunset_len;
    uint32_t            tail_cap;   /* alloc'd tail bytes beyond key+group */
    u_char              data[];
} ngx_http_xngin_cache_node_t;


static void
ngx_http_xngin_cache_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;

    for ( ;; ) {
        p = (node->key < temp->key) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_http_xngin_cache_shctx_t *
ngx_http_xngin_cache_sh(ngx_http_xngin_main_conf_t *mmcf)
{
    if (mmcf->cache_zone == NULL) {
        return NULL;
    }

    return mmcf->cache_zone->data;
}


/* find the node whose stored (group, key) pair byte-matches among the
   nodes sharing tree key `key_h` — the node identity is the group name
   PLUS the key bytes, so different groups can hold entries for the
   same key side by side (crc32 collisions also insert equal tree keys;
   rbtree rotations can park them in either subtree, so an equal-key
   node requires walking both children).  Caller holds the slab mutex. */
static ngx_http_xngin_cache_node_t *
ngx_http_xngin_cache_find(ngx_http_xngin_cache_shctx_t *sh,
    ngx_rbtree_node_t *node, uint64_t key_h, u_char *kdata, size_t klen,
    u_char *gdata, size_t glen)
{
    ngx_http_xngin_cache_node_t *n, *f;

    if (node == sh->rbtree.sentinel) {
        return NULL;
    }

    if ((ngx_rbtree_key_t) key_h < node->key) {
        return ngx_http_xngin_cache_find(sh, node->left, key_h,
                                         kdata, klen, gdata, glen);
    }

    if ((ngx_rbtree_key_t) key_h > node->key) {
        return ngx_http_xngin_cache_find(sh, node->right, key_h,
                                         kdata, klen, gdata, glen);
    }

    n = (ngx_http_xngin_cache_node_t *) node;

    if (n->key_len == klen && n->group_len == glen
        && ngx_memcmp(n->data, kdata, klen) == 0
        && ngx_memcmp(n->data + n->key_len, gdata, glen) == 0)
    {
        return n;
    }

    f = ngx_http_xngin_cache_find(sh, node->left, key_h, kdata, klen,
                                  gdata, glen);
    if (f) {
        return f;
    }

    return ngx_http_xngin_cache_find(sh, node->right, key_h, kdata, klen,
                                     gdata, glen);
}


static void
ngx_http_xngin_cache_node_free(ngx_http_xngin_cache_shctx_t *sh,
    ngx_slab_pool_t *shpool, ngx_http_xngin_cache_node_t *n)
{
    ngx_queue_remove(&n->queue);
    ngx_rbtree_delete(&sh->rbtree, &n->node);
    ngx_slab_free_locked(shpool, n);
    if (sh->nentries) {
        sh->nentries--;
    }
}


static void
ngx_http_xngin_cache_expire_locked(ngx_http_xngin_cache_shctx_t *sh,
    ngx_slab_pool_t *shpool)
{
    ngx_http_xngin_cache_node_t *n;
    ngx_queue_t                 *q;
    time_t                       now = ngx_time();

    while (!ngx_queue_empty(&sh->queue)) {
        q = ngx_queue_last(&sh->queue);
        n = ngx_queue_data(q, ngx_http_xngin_cache_node_t, queue);

        if (n->expire > now) {
            return;
        }

        ngx_http_xngin_cache_node_free(sh, shpool, n);
    }
}


/* populate ctx (deny payload + res-hdr ops) from a node's staged tail
   copy; runs after the slab mutex is released */
static void
ngx_http_xngin_cache_unpack(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx, ngx_http_xngin_cache_node_t *n,
    u_char *tail)
{
    u_char               *p, *end;
    ngx_http_xngin_var_t *kv;
    ngx_str_t            *nm;
    uint64_t              cnt;

    p = tail;
    end = tail + n->reason_len + n->body_len + n->ctype_len
          + n->hdrset_len + n->hdrunset_len;

    ctx->reason.len = n->reason_len;
    ctx->reason.data = p;
    p += n->reason_len;

    ctx->deny_body.len = n->body_len;
    ctx->deny_body.data = p;
    p += n->body_len;

    ctx->deny_ctype.len = n->ctype_len;
    ctx->deny_ctype.data = p;
    p += n->ctype_len;

    if (n->hdrset_len >= 2) {
        cnt = ((uint64_t) p[0] << 8) | p[1];
        p += 2;

        while (cnt-- && p + 2 <= end) {
            size_t nl = ((size_t) p[0] << 8) | p[1];
            size_t vl;
            p += 2;
            if (p + nl + 2 > end) {
                break;
            }
            if (ctx->res_hdr_set == NULL) {
                ctx->res_hdr_set = ngx_array_create(r->pool, 4,
                                          sizeof(ngx_http_xngin_var_t));
            }
            if (ctx->res_hdr_set) {
                kv = ngx_array_push(ctx->res_hdr_set);
            } else {
                kv = NULL;
            }
            if (kv) {
                kv->name.len = nl;
                kv->name.data = p;
            }
            p += nl;
            vl = ((size_t) p[0] << 8) | p[1];
            p += 2;
            if (p + vl > end) {
                break;
            }
            if (kv) {
                kv->value.len = vl;
                kv->value.data = p;
            }
            p += vl;
        }
    }

    if (n->hdrunset_len >= 2) {
        cnt = ((uint64_t) p[0] << 8) | p[1];
        p += 2;

        while (cnt-- && p + 2 <= end) {
            size_t nl = ((size_t) p[0] << 8) | p[1];
            p += 2;
            if (p + nl > end) {
                break;
            }
            nm = NULL;
            if (ctx->res_hdr_unset == NULL) {
                ctx->res_hdr_unset = ngx_array_create(r->pool, 4,
                                                    sizeof(ngx_str_t));
            }
            if (ctx->res_hdr_unset) {
                nm = ngx_array_push(ctx->res_hdr_unset);
            }
            if (nm) {
                nm->len = nl;
                nm->data = p;
            }
            p += nl;
        }
    }
}


ngx_int_t
ngx_http_xngin_cache_lookup(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx, ngx_str_t *key, ngx_str_t *group,
    ngx_int_t *out_status)
{
    ngx_http_xngin_main_conf_t   *mmcf;
    ngx_http_xngin_cache_shctx_t *sh;
    ngx_http_xngin_cache_node_t  *n, hn;
    ngx_slab_pool_t              *shpool;
    uint64_t                      key_h;
    size_t                        tail_len, tail_cap;
    u_char                       *tail, *gdata;
    size_t                        glen;
    ngx_uint_t                    tries;

    mmcf = ngx_http_get_module_main_conf(r, ngx_http_xngin_module);
    sh = ngx_http_xngin_cache_sh(mmcf);

    if (sh == NULL) {
        ctx->cache_status = XNAP_CACHE_DISABLED;
        return NGX_DECLINED;
    }

    key_h = ngx_crc32_long(key->data, key->len);
    shpool = (ngx_slab_pool_t *) mmcf->cache_zone->shm.addr;

    gdata = (group != NULL) ? group->data : (u_char *) "";
    glen = (group != NULL) ? group->len : 0;

    tail = NULL;
    tail_cap = 0;

    for (tries = 0; tries < 3; tries++) {

        ngx_shmtx_lock(&shpool->mutex);

        /* re-find each round: the node may have been evicted or
           refreshed by another worker while the lock was dropped;
           an entry owned by another group stays a miss */
        n = ngx_http_xngin_cache_find(sh, sh->rbtree.root, key_h,
                                      key->data, key->len, gdata, glen);

        if (n && n->expire <= ngx_time()) {
            ngx_http_xngin_cache_node_free(sh, shpool, n);
            n = NULL;
        }

        if (n == NULL) {
            sh->nmiss++;
            ngx_shmtx_unlock(&shpool->mutex);
            ctx->cache_status = XNAP_CACHE_MISS;
            return NGX_DECLINED;
        }

        ngx_queue_remove(&n->queue);
        ngx_queue_insert_head(&sh->queue, &n->queue);

        hn = *n;   /* header copy under lock — node may be freed after it */

        tail_len = (size_t) n->reason_len + n->body_len + n->ctype_len
                   + n->hdrset_len + n->hdrunset_len;

        if (tail_len > tail_cap) {
            /* grow outside the lock — a pool-growth malloc must not
               stall every worker's cache traffic */
            ngx_shmtx_unlock(&shpool->mutex);
            tail = ngx_pnalloc(r->pool, tail_len);
            if (tail == NULL) {
                /* a cached deny must fail closed; an allow can just
                   re-dispatch as a miss */
                if (hn.action != NGX_DECLINED) {
                    *out_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    return NGX_OK;
                }
                ctx->cache_status = XNAP_CACHE_MISS;
                return NGX_DECLINED;
            }
            tail_cap = tail_len;
            continue;
        }

        ngx_memcpy(tail, n->data + n->key_len + n->group_len, tail_len);

        sh->nhit++;
        ngx_shmtx_unlock(&shpool->mutex);

        *out_status = hn.action;
        ctx->score = hn.score;

        ngx_http_xngin_cache_unpack(r, ctx, &hn, tail);

        ctx->cache_status = XNAP_CACHE_HIT;
        return NGX_OK;
    }

    /* node kept mutating between rounds — treat as a miss rather than
       replaying a half-read entry */
    ctx->cache_status = XNAP_CACHE_MISS;
    return NGX_DECLINED;
}


/* hdr-set blob length: u16 count + per entry u16 nlen + name + u16 vlen + val */
static size_t
ngx_http_xngin_kv_tail_len(ngx_array_t *a)
{
    ngx_http_xngin_var_t  *kv;
    ngx_uint_t             i;
    size_t                 n = 2;

    if (a == NULL) {
        return n;
    }

    kv = a->elts;
    for (i = 0; i < a->nelts; i++) {
        n += 2 + kv[i].name.len + 2 + kv[i].value.len;
    }

    return n;
}


/* hdr-unset blob length: u16 count + per entry u16 nlen + name */
static size_t
ngx_http_xngin_str_tail_len(ngx_array_t *a)
{
    ngx_str_t   *nm;
    ngx_uint_t   i;
    size_t       n = 2;

    if (a == NULL) {
        return n;
    }

    nm = a->elts;
    for (i = 0; i < a->nelts; i++) {
        n += 2 + nm[i].len;
    }

    return n;
}


void
ngx_http_xngin_cache_store(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx, ngx_str_t *key, uint32_t ttl,
    ngx_str_t *group)
{
    ngx_http_xngin_main_conf_t   *mmcf;
    ngx_http_xngin_cache_shctx_t *sh;
    ngx_http_xngin_cache_node_t  *n;
    ngx_slab_pool_t              *shpool;
    size_t                        size, tail_len;
    uint64_t                      key_h;
    ngx_int_t                     action;
    u_short                       rlen, ctlen;
    u_char                       *p;
    ngx_http_xngin_var_t         *kv;
    ngx_str_t                    *nm;
    ngx_uint_t                    i;

    mmcf = ngx_http_get_module_main_conf(r, ngx_http_xngin_module);
    sh = ngx_http_xngin_cache_sh(mmcf);

    if (sh == NULL || key == NULL || key->len == 0
        || key->len > 1024 || ttl == 0)
    {
        return;
    }

    action = ctx->deny_status ? ctx->deny_status : (ngx_int_t) NGX_DECLINED;

    rlen = (u_short) ngx_min(ctx->reason.len, XNAP_CACHE_REASON_MAX);
    ctlen = (u_short) ngx_min(ctx->deny_ctype.len, 256);

    tail_len = rlen + ctx->deny_body.len + ctlen
               + ngx_http_xngin_kv_tail_len(ctx->res_hdr_set)
               + ngx_http_xngin_str_tail_len(ctx->res_hdr_unset);

    if (ctx->deny_body.len > XNAP_CACHE_BODY_MAX
        || tail_len > XNAP_CACHE_NODE_MAX)
    {
        return;
    }

    if (group == NULL || group->len > 256) {
        group = NULL;
    }

    key_h = ngx_crc32_long(key->data, key->len);
    size = sizeof(ngx_http_xngin_cache_node_t) + key->len
           + (group ? group->len : 0) + tail_len;

    shpool = (ngx_slab_pool_t *) mmcf->cache_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    ngx_http_xngin_cache_expire_locked(sh, shpool);

    /* replace this group's byte-equal key in place — never park a dead
       duplicate behind it (a same-key second verdict arrives e.g. when
       requests for the key interleave across the agent round-trip).
       A same-key node owned by another group is simply not found and
       stays in the tree untouched. */
    n = ngx_http_xngin_cache_find(sh, sh->rbtree.root, key_h,
                                  key->data, key->len,
                                  group ? group->data : (u_char *) "",
                                  group ? group->len : 0);

    if (n && tail_len <= n->tail_cap) {
        n->expire = ngx_time() + ttl;
        n->action = action;
        n->score = ctx->score;

        ngx_queue_remove(&n->queue);
        ngx_queue_insert_head(&sh->queue, &n->queue);

        goto fill;
    }

    if (n) {
        /* same (group, key), bigger tail: out with the old node */
        ngx_http_xngin_cache_node_free(sh, shpool, n);
    }

    n = ngx_slab_alloc_locked(shpool, size);

    if (n == NULL && !ngx_queue_empty(&sh->queue)) {
        /* force-evict LRU tail and retry once */
        ngx_queue_t                 *q = ngx_queue_last(&sh->queue);
        ngx_http_xngin_cache_node_t *victim;

        victim = ngx_queue_data(q, ngx_http_xngin_cache_node_t, queue);
        ngx_http_xngin_cache_node_free(sh, shpool, victim);

        n = ngx_slab_alloc_locked(shpool, size);
    }

    if (n == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return;
    }

    n->node.key = (ngx_rbtree_key_t) key_h;
    n->key_h = key_h;
    n->expire = ngx_time() + ttl;
    n->action = action;
    n->score = ctx->score;
    n->key_len = (u_short) key->len;
    n->group_len = (u_short) (group ? group->len : 0);
    n->tail_cap = tail_len;

    p = n->data;
    ngx_memcpy(p, key->data, key->len);
    p += key->len;
    if (group) {
        ngx_memcpy(p, group->data, group->len);
    }

    ngx_rbtree_insert(&sh->rbtree, &n->node);
    ngx_queue_insert_head(&sh->queue, &n->queue);
    sh->nentries++;

fill:

    n->reason_len = rlen;
    n->body_len = ctx->deny_body.len;
    n->ctype_len = ctlen;
    n->hdrset_len = ngx_http_xngin_kv_tail_len(ctx->res_hdr_set);
    n->hdrunset_len = ngx_http_xngin_str_tail_len(ctx->res_hdr_unset);

    p = n->data + n->key_len + n->group_len;

    ngx_memcpy(p, ctx->reason.data, rlen);
    p += rlen;
    ngx_memcpy(p, ctx->deny_body.data, ctx->deny_body.len);
    p += ctx->deny_body.len;
    ngx_memcpy(p, ctx->deny_ctype.data, ctlen);
    p += ctlen;

    /* res-hdr-set blob */
    *p++ = (u_char) ((ctx->res_hdr_set ? ctx->res_hdr_set->nelts : 0)
                     >> 8);
    *p++ = (u_char) ((ctx->res_hdr_set ? ctx->res_hdr_set->nelts : 0)
                     & 0xff);
    if (ctx->res_hdr_set) {
        kv = ctx->res_hdr_set->elts;
        for (i = 0; i < ctx->res_hdr_set->nelts; i++) {
            *p++ = (u_char) (kv[i].name.len >> 8);
            *p++ = (u_char) (kv[i].name.len & 0xff);
            p = ngx_cpymem(p, kv[i].name.data, kv[i].name.len);
            *p++ = (u_char) (kv[i].value.len >> 8);
            *p++ = (u_char) (kv[i].value.len & 0xff);
            p = ngx_cpymem(p, kv[i].value.data, kv[i].value.len);
        }
    }

    /* res-hdr-unset blob */
    *p++ = (u_char) ((ctx->res_hdr_unset ? ctx->res_hdr_unset->nelts : 0)
                     >> 8);
    *p++ = (u_char) ((ctx->res_hdr_unset ? ctx->res_hdr_unset->nelts : 0)
                     & 0xff);
    if (ctx->res_hdr_unset) {
        nm = ctx->res_hdr_unset->elts;
        for (i = 0; i < ctx->res_hdr_unset->nelts; i++) {
            *p++ = (u_char) (nm[i].len >> 8);
            *p++ = (u_char) (nm[i].len & 0xff);
            p = ngx_cpymem(p, nm[i].data, nm[i].len);
        }
    }

    ngx_shmtx_unlock(&shpool->mutex);
}


/* CONTROL cache-drop: delete a verdict-cache entry by its raw key —
   only when the requesting group is the one that stored it */
void
ngx_http_xngin_cache_drop(ngx_http_xngin_main_conf_t *mmcf, ngx_str_t *key,
    ngx_str_t *group)
{
    ngx_http_xngin_cache_shctx_t *sh;
    ngx_http_xngin_cache_node_t  *n;
    ngx_slab_pool_t              *shpool;
    uint64_t                      key_h;

    sh = ngx_http_xngin_cache_sh(mmcf);
    if (sh == NULL || key == NULL || key->len == 0 || key->len > 1024
        || group == NULL)
    {
        return;
    }

    key_h = ngx_crc32_long(key->data, key->len);
    shpool = (ngx_slab_pool_t *) mmcf->cache_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    n = ngx_http_xngin_cache_find(sh, sh->rbtree.root, key_h,
                                  key->data, key->len,
                                  group->data, group->len);
    if (n) {
        ngx_http_xngin_cache_node_free(sh, shpool, n);
    }

    ngx_shmtx_unlock(&shpool->mutex);
}


ngx_int_t
ngx_http_xngin_cache_zone_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_xngin_cache_shctx_t *sh;
    ngx_slab_pool_t              *shpool;

    if (data) {
        /* inherited zone across reload */
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = ngx_slab_alloc(shpool, sizeof(ngx_http_xngin_cache_shctx_t));

    if (sh == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&sh->rbtree, &sh->sentinel,
                    ngx_http_xngin_cache_rbtree_insert);

    ngx_queue_init(&sh->queue);
    sh->nhit = 0;
    sh->nmiss = 0;
    sh->nentries = 0;

    shm_zone->data = sh;

    return NGX_OK;
}
