#include "ngx_http_xngin_module.h"


/*
 * Agent-pushed bans (CONTROL frame ops ban-ip / ban-ja4).  Entries live
 * in the shared xngin_ban_zone when configured — enforced identically
 * across workers — otherwise in a per-worker rbtree fallback.
 */

typedef struct {
    ngx_rbtree_node_t  node;
    time_t             expire;
    ngx_queue_t        queue;
    uint16_t           key_len;
    u_char             data[];
} ngx_xngin_ban_node_t;

typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;
    ngx_uint_t         nentries;
} ngx_xngin_ban_store_t;

typedef struct {
    ngx_xngin_ban_store_t  stores[2];   /* XNAP_BAN_IP / XNAP_BAN_JA4 */
} ngx_xngin_ban_shctx_t;

#define XNAP_BAN_MAX_KEY     256
#define XNAP_BAN_LOCAL_CAP   1024


static ngx_xngin_ban_shctx_t ngx_xngin_ban_local;
static ngx_uint_t            ngx_xngin_ban_local_ready;


static void
ngx_xngin_ban_rbtree_insert(ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t    **p;
    ngx_xngin_ban_node_t *n, *t;

    for ( ;; ) {
        n = (ngx_xngin_ban_node_t *) node;
        t = (ngx_xngin_ban_node_t *) root;

        if (node->key != root->key) {
            p = (node->key < root->key) ? &root->left : &root->right;
        } else {
            /* equal crc: byte compare the full key */
            ngx_int_t rc = ngx_memn2cmp(n->data, t->data,
                                      n->key_len, t->key_len);
            p = (rc < 0) ? &root->left : &root->right;
        }

        if (*p == sentinel) {
            break;
        }
        root = *p;
    }

    *p = node;
    node->parent = root;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static void
ngx_xngin_ban_store_init(ngx_xngin_ban_store_t *st)
{
    ngx_rbtree_init(&st->rbtree, &st->sentinel,
                    ngx_xngin_ban_rbtree_insert);
    ngx_queue_init(&st->queue);
    st->nentries = 0;
}


static ngx_xngin_ban_store_t *
ngx_xngin_ban_store(ngx_http_xngin_main_conf_t *mmcf, ngx_uint_t kind,
    ngx_slab_pool_t **shpool_out)
{
    ngx_xngin_ban_shctx_t *sh;

    *shpool_out = NULL;

    if (mmcf->ban_zone && mmcf->ban_zone->data) {
        *shpool_out = (ngx_slab_pool_t *) mmcf->ban_zone->shm.addr;
        sh = mmcf->ban_zone->data;
        return &sh->stores[kind];
    }

    if (!ngx_xngin_ban_local_ready) {
        ngx_xngin_ban_store_init(&ngx_xngin_ban_local.stores[0]);
        ngx_xngin_ban_store_init(&ngx_xngin_ban_local.stores[1]);
        ngx_xngin_ban_local_ready = 1;
    }

    return &ngx_xngin_ban_local.stores[kind];
}


static ngx_xngin_ban_node_t *
ngx_xngin_ban_find(ngx_xngin_ban_store_t *st, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel, uint32_t hash, u_char *key, uint16_t len)
{
    ngx_xngin_ban_node_t *n;

    while (node != sentinel) {
        n = (ngx_xngin_ban_node_t *) node;

        if (hash < node->key) {
            node = node->left;
            continue;
        }
        if (hash > node->key) {
            node = node->right;
            continue;
        }
        if (n->key_len == len
            && ngx_memcmp(n->data, key, len) == 0)
        {
            return n;
        }
        /* equal hash collision: walk both subtrees */
        {
            ngx_xngin_ban_node_t *m;
            m = ngx_xngin_ban_find(st, node->left, sentinel,
                                   hash, key, len);
            if (m) {
                return m;
            }
            node = node->right;
        }
    }

    return NULL;
}


static void
ngx_xngin_ban_node_free(ngx_xngin_ban_store_t *st,
    ngx_slab_pool_t *shpool, ngx_xngin_ban_node_t *n)
{
    ngx_rbtree_delete(&st->rbtree, &n->node);
    ngx_queue_remove(&n->queue);
    st->nentries--;
    if (shpool) {
        ngx_slab_free_locked(shpool, n);
    } else {
        ngx_free(n);
    }
}


static void
ngx_xngin_ban_expire(ngx_xngin_ban_store_t *st, ngx_slab_pool_t *shpool)
{
    ngx_queue_t           *q;
    ngx_xngin_ban_node_t  *n;
    time_t                 now = ngx_time();

    while (!ngx_queue_empty(&st->queue)) {
        q = ngx_queue_last(&st->queue);
        n = ngx_queue_data(q, ngx_xngin_ban_node_t, queue);
        if (n->expire > now) {
            return;
        }
        ngx_xngin_ban_node_free(st, shpool, n);
    }
}


ngx_int_t
ngx_http_xngin_ban_zone_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_xngin_ban_shctx_t *sh;
    ngx_slab_pool_t       *shpool;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = ngx_slab_alloc(shpool, sizeof(ngx_xngin_ban_shctx_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }

    ngx_xngin_ban_store_init(&sh->stores[0]);
    ngx_xngin_ban_store_init(&sh->stores[1]);
    shm_zone->data = sh;

    return NGX_OK;
}


void
ngx_http_xngin_ban_add(ngx_http_xngin_main_conf_t *mmcf, ngx_uint_t kind,
    ngx_str_t *key, uint32_t ttl)
{
    ngx_xngin_ban_store_t *st;
    ngx_xngin_ban_node_t  *n;
    ngx_slab_pool_t       *shpool;
    uint32_t               hash;
    size_t                 size;

    if (key == NULL || key->len == 0 || key->len > XNAP_BAN_MAX_KEY) {
        return;
    }

    st = ngx_xngin_ban_store(mmcf, kind, &shpool);
    hash = ngx_crc32_long(key->data, key->len);

    if (shpool) {
        ngx_shmtx_lock(&shpool->mutex);
    }

    ngx_xngin_ban_expire(st, shpool);

    n = ngx_xngin_ban_find(st, st->rbtree.root, &st->sentinel,
                           hash, key->data, key->len);
    if (n) {
        n->expire = ngx_time() + ttl;
        ngx_queue_remove(&n->queue);
        ngx_queue_insert_head(&st->queue, &n->queue);
        goto done;
    }

    size = offsetof(ngx_xngin_ban_node_t, data) + key->len;
    n = shpool ? ngx_slab_alloc_locked(shpool, size) : ngx_alloc(size,
                                                               ngx_cycle->log);
    if (n == NULL) {
        /* local fallback cap: evict oldest */
        if (!shpool && st->nentries >= XNAP_BAN_LOCAL_CAP
            && !ngx_queue_empty(&st->queue))
        {
            ngx_xngin_ban_node_free(st, shpool,
                ngx_queue_data(ngx_queue_last(&st->queue),
                               ngx_xngin_ban_node_t, queue));
            n = ngx_alloc(size, ngx_cycle->log);
        }
        if (n == NULL) {
            goto done;
        }
    }

    n->node.key = hash;
    n->expire = ngx_time() + ttl;
    n->key_len = (uint16_t) key->len;
    ngx_memcpy(n->data, key->data, key->len);

    ngx_rbtree_insert(&st->rbtree, &n->node);
    ngx_queue_insert_head(&st->queue, &n->queue);
    st->nentries++;

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "xngin: %s ban added for \"%V\" (ttl %ui)",
                  kind == XNAP_BAN_IP ? "ip" : "ja4", key, ttl);

done:
    if (shpool) {
        ngx_shmtx_unlock(&shpool->mutex);
    }
}


ngx_int_t
ngx_http_xngin_ban_check(ngx_http_xngin_main_conf_t *mmcf, ngx_uint_t kind,
    ngx_str_t *key)
{
    ngx_xngin_ban_store_t *st;
    ngx_xngin_ban_node_t  *n;
    ngx_slab_pool_t       *shpool;
    uint32_t               hash;
    ngx_int_t              banned = 0;

    if (key == NULL || key->len == 0 || key->len > XNAP_BAN_MAX_KEY) {
        return 0;
    }

    st = ngx_xngin_ban_store(mmcf, kind, &shpool);

    /* fast path: nothing banned at all */
    if (st->nentries == 0) {
        return 0;
    }

    hash = ngx_crc32_long(key->data, key->len);

    if (shpool) {
        ngx_shmtx_lock(&shpool->mutex);
    }

    n = ngx_xngin_ban_find(st, st->rbtree.root, &st->sentinel,
                           hash, key->data, key->len);
    if (n) {
        if (n->expire <= ngx_time()) {
            ngx_xngin_ban_node_free(st, shpool, n);
        } else {
            banned = 1;
        }
    }

    if (shpool) {
        ngx_shmtx_unlock(&shpool->mutex);
    }

    return banned;
}


/* ---------- CONTROL frame (agent-pushed ops, even sids) ---------- */

ngx_int_t
ngx_http_xngin_control(ngx_http_xngin_conn_t *c, u_char *payload,
    size_t len)
{
    ngx_http_xngin_main_conf_t *mmcf;
    ngx_xnap_rbuf_t             rb;
    ngx_str_t                   name;
    ngx_xnap_val_t              v;
    ngx_str_t                   op = ngx_null_string;
    ngx_str_t                   ip = ngx_null_string;
    ngx_str_t                   ja4 = ngx_null_string;
    ngx_str_t                   key = ngx_null_string;
    uint64_t                    ttl = 300;
    ngx_int_t                   rc;

    rb.pos = payload;
    rb.end = payload + len;
    rb.err = 0;

    while ((rc = ngx_xnap_rbuf_kv(&rb, &name, &v)) == NGX_OK) {

        if (name.len == 2 && ngx_memcmp(name.data, "op", 2) == 0) {
            op = v.s;
        } else if (name.len == 2 && ngx_memcmp(name.data, "ip", 2) == 0) {
            ip = v.s;
        } else if (name.len == 3 && ngx_memcmp(name.data, "ja4", 3) == 0) {
            ja4 = v.s;
        } else if (name.len == 3 && ngx_memcmp(name.data, "key", 3) == 0) {
            key = v.s;
        } else if (name.len == 3 && ngx_memcmp(name.data, "ttl", 3) == 0) {
            ttl = v.u;
        }
    }

    mmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_xngin_module);
    if (mmcf == NULL || op.len == 0) {
        return NGX_OK;
    }

    if (op.len == 6 && ngx_memcmp(op.data, "ban-ip", 6) == 0) {
        if (ip.len) {
            ngx_http_xngin_ban_add(mmcf, XNAP_BAN_IP, &ip, (uint32_t) ttl);
        }
        return NGX_OK;
    }

    if (op.len == 7 && ngx_memcmp(op.data, "ban-ja4", 7) == 0) {
        if (ja4.len) {
            ngx_http_xngin_ban_add(mmcf, XNAP_BAN_JA4, &ja4,
                                   (uint32_t) ttl);
        }
        return NGX_OK;
    }

    if (op.len == 10 && ngx_memcmp(op.data, "cache-drop", 10) == 0) {
        ngx_http_xngin_cache_drop(mmcf, &key);
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "xngin: unknown CONTROL op \"%V\" from %V",
                  &op, &c->agent->url_text);

    return NGX_OK;
}
