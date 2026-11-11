#include "ngx_http_xngin_module.h"


typedef struct {
    ngx_rbtree_node_t   node;
    ngx_queue_t         queue;
    uint64_t            key_h;
    time_t              expire;
    ngx_int_t           action;     /* NGX_DECLINED (allow) or HTTP status */
    int64_t             score;
    u_short             key_len;
    u_short             reason_len;
    u_char              data[];     /* key bytes then reason bytes */
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

        ngx_queue_remove(q);
        ngx_rbtree_delete(&sh->rbtree, &n->node);
        ngx_slab_free_locked(shpool, n);
    }
}


ngx_int_t
ngx_http_xngin_cache_lookup(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx, ngx_str_t *key,
    ngx_int_t *out_status, int64_t *out_score, ngx_str_t *out_reason)
{
    ngx_http_xngin_main_conf_t   *mmcf;
    ngx_http_xngin_cache_shctx_t *sh;
    ngx_http_xngin_cache_node_t  *n;
    ngx_slab_pool_t              *shpool;
    uint64_t                      key_h;
    ngx_rbtree_node_t            *node, *sentinel;

    mmcf = ngx_http_get_module_main_conf(r, ngx_http_xngin_module);
    sh = ngx_http_xngin_cache_sh(mmcf);

    if (sh == NULL) {
        ctx->cache_status = XNAP_CACHE_DISABLED;
        return NGX_DECLINED;
    }

    key_h = ngx_crc32_long(key->data, key->len);
    shpool = (ngx_slab_pool_t *) mmcf->cache_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    sentinel = sh->rbtree.sentinel;
    node = sh->rbtree.root;

    while (node != sentinel) {
        if ((ngx_rbtree_key_t) key_h < node->key) {
            node = node->left;
            continue;
        }
        if ((ngx_rbtree_key_t) key_h > node->key) {
            node = node->right;
            continue;
        }

        n = (ngx_http_xngin_cache_node_t *) node;

        if (n->key_len == key->len
            && ngx_memcmp(n->data, key->data, key->len) == 0)
        {
            if (n->expire <= ngx_time()) {
                ngx_queue_remove(&n->queue);
                ngx_rbtree_delete(&sh->rbtree, node);
                ngx_slab_free_locked(shpool, n);
                break;
            }

            ngx_queue_remove(&n->queue);
            ngx_queue_insert_head(&sh->queue, &n->queue);

            *out_status = n->action;
            *out_score = n->score;
            out_reason->data = ngx_pnalloc(r->pool, n->reason_len);
            ngx_memcpy(out_reason->data,
                       n->data + n->key_len, n->reason_len);
            out_reason->len = n->reason_len;

            sh->nhit++;
            ngx_shmtx_unlock(&shpool->mutex);

            ctx->cache_status = XNAP_CACHE_HIT;
            return NGX_OK;
        }

        break;
    }

    sh->nmiss++;
    ngx_shmtx_unlock(&shpool->mutex);

    ctx->cache_status = XNAP_CACHE_MISS;
    return NGX_DECLINED;
}


void
ngx_http_xngin_cache_store(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx, ngx_str_t *key, uint32_t ttl)
{
    ngx_http_xngin_main_conf_t   *mmcf;
    ngx_http_xngin_cache_shctx_t *sh;
    ngx_http_xngin_cache_node_t  *n;
    ngx_slab_pool_t              *shpool;
    size_t                        size;
    uint64_t                      key_h;
    ngx_int_t                     action;

    mmcf = ngx_http_get_module_main_conf(r, ngx_http_xngin_module);
    sh = ngx_http_xngin_cache_sh(mmcf);

    if (sh == NULL || key == NULL || key->len == 0
        || key->len > 1024 || ttl == 0)
    {
        return;
    }

    action = ctx->deny_status ? ctx->deny_status : (ngx_int_t) NGX_DECLINED;

    key_h = ngx_crc32_long(key->data, key->len);
    size = sizeof(ngx_http_xngin_cache_node_t) + key->len + ctx->reason.len;

    shpool = (ngx_slab_pool_t *) mmcf->cache_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    ngx_http_xngin_cache_expire_locked(sh, shpool);

    n = ngx_slab_alloc_locked(shpool, size);

    if (n == NULL && !ngx_queue_empty(&sh->queue)) {
        /* force-evict LRU tail and retry once */
        ngx_queue_t                 *q = ngx_queue_last(&sh->queue);
        ngx_http_xngin_cache_node_t *victim;

        victim = ngx_queue_data(q, ngx_http_xngin_cache_node_t, queue);
        ngx_queue_remove(q);
        ngx_rbtree_delete(&sh->rbtree, &victim->node);
        ngx_slab_free_locked(shpool, victim);

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
    n->reason_len = (u_short) ctx->reason.len;

    ngx_memcpy(n->data, key->data, key->len);
    ngx_memcpy(n->data + key->len, ctx->reason.data, ctx->reason.len);

    ngx_rbtree_insert(&sh->rbtree, &n->node);
    ngx_queue_insert_head(&sh->queue, &n->queue);

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

    shm_zone->data = sh;

    return NGX_OK;
}
