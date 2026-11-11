#include "ngx_http_xngin_module.h"


static void *ngx_http_xngin_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_xngin_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_xngin_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void *ngx_http_xngin_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_xngin_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_xngin_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_xngin_init_process(ngx_cycle_t *cycle);
static void ngx_http_xngin_exit_process(ngx_cycle_t *cycle);

static char *ngx_http_xngin_agent_group(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_agent_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_cache_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_mode(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_fail_mode(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_cache_key_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_tls_deny_add(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_xngin_handler(ngx_http_request_t *r);
static void ngx_http_xngin_body_post(ngx_http_request_t *r);
static void ngx_http_xngin_req_cleanup(void *data);
static void ngx_http_xngin_launch(ngx_http_request_t *r,
    ngx_http_xngin_ctx_t *ctx, ngx_http_xngin_loc_conf_t *lcf);

static ngx_int_t ngx_http_xngin_var_action(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_xngin_var_score(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_xngin_var_reason(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_xngin_var_error(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_xngin_var_rtt(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_xngin_var_cache(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_xngin_var_ja4(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_xngin_var_prefix(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_command_t ngx_http_xngin_commands[] = {

    { ngx_string("xngin_agent_group"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_xngin_agent_group,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xngin_cache_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_xngin_cache_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xngin_enable"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, enable),
      NULL },

    { ngx_string("xngin_group"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, group_name),
      NULL },

    { ngx_string("xngin_mode"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_xngin_mode,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, mode),
      NULL },

    { ngx_string("xngin_timeout"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, timeout),
      NULL },

    { ngx_string("xngin_fail"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_xngin_fail_mode,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, fail),
      NULL },

    { ngx_string("xngin_body_inspect"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, body_inspect),
      NULL },

    { ngx_string("xngin_body_max"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, body_max),
      NULL },

    { ngx_string("xngin_response"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, response),
      NULL },

    { ngx_string("xngin_res_body_max"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, res_body_max),
      NULL },

    { ngx_string("xngin_cache_key"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_xngin_cache_key_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xngin_tls_inspect"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_xngin_srv_conf_t, tls_inspect),
      NULL },

    { ngx_string("xngin_tls_deny"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_xngin_tls_deny_add,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_xngin_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_xngin_init,                   /* postconfiguration */

    ngx_http_xngin_create_main_conf,       /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_xngin_create_srv_conf,        /* create server configuration */
    ngx_http_xngin_merge_srv_conf,         /* merge server configuration */

    ngx_http_xngin_create_loc_conf,        /* create location configuration */
    ngx_http_xngin_merge_loc_conf          /* merge location configuration */
};


ngx_module_t ngx_http_xngin_module = {
    NGX_MODULE_V1,
    &ngx_http_xngin_module_ctx,            /* module context */
    ngx_http_xngin_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_xngin_init_process,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_xngin_exit_process,           /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_xngin_vars[] = {

    { ngx_string("xngin_action"), NULL,
      ngx_http_xngin_var_action, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("xngin_score"), NULL,
      ngx_http_xngin_var_score, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("xngin_reason"), NULL,
      ngx_http_xngin_var_reason, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("xngin_error"), NULL,
      ngx_http_xngin_var_error, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("xngin_agent_rtt_us"), NULL,
      ngx_http_xngin_var_rtt, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("xngin_cache"), NULL,
      ngx_http_xngin_var_cache, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("xngin_ja4"), NULL,
      ngx_http_xngin_var_ja4, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("xngin_"), NULL,
      ngx_http_xngin_var_prefix, 0,
      NGX_HTTP_VAR_PREFIX|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE,
      0 },

      ngx_http_null_variable
};


/* ---------- conf ---------- */

static void *
ngx_http_xngin_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_xngin_main_conf_t *mmcf;

    mmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_xngin_main_conf_t));
    if (mmcf == NULL) {
        return NULL;
    }

    return mmcf;
}


static void *
ngx_http_xngin_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_xngin_srv_conf_t *xscf;

    xscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_xngin_srv_conf_t));
    if (xscf == NULL) {
        return NULL;
    }

    xscf->tls_inspect = NGX_CONF_UNSET;

    return xscf;
}


static char *
ngx_http_xngin_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_xngin_srv_conf_t *prev = parent;
    ngx_http_xngin_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->tls_inspect, prev->tls_inspect, 0);

    if (conf->tls_deny == NULL) {
        conf->tls_deny = prev->tls_deny;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_xngin_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_xngin_loc_conf_t *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_xngin_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->enable = NGX_CONF_UNSET;
    lcf->mode = NGX_CONF_UNSET_UINT;
    lcf->timeout = NGX_CONF_UNSET_MSEC;
    lcf->fail = NGX_CONF_UNSET_UINT;
    lcf->body_inspect = NGX_CONF_UNSET;
    lcf->body_max = NGX_CONF_UNSET_SIZE;
    lcf->response = NGX_CONF_UNSET;
    lcf->res_body_max = NGX_CONF_UNSET_SIZE;
    lcf->cache_key = NGX_CONF_UNSET_PTR;

    return lcf;
}


static char *
ngx_http_xngin_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_xngin_loc_conf_t  *prev = parent;
    ngx_http_xngin_loc_conf_t  *conf = child;
    ngx_http_xngin_main_conf_t *mmcf;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_uint_t                  i;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->group_name, prev->group_name, "");
    ngx_conf_merge_uint_value(conf->mode, prev->mode, XNAP_MODE_BLOCKING);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 50);
    ngx_conf_merge_uint_value(conf->fail, prev->fail, XNAP_FAIL_CLOSE);
    ngx_conf_merge_value(conf->body_inspect, prev->body_inspect, 0);
    ngx_conf_merge_size_value(conf->body_max, prev->body_max, 64 * 1024);
    ngx_conf_merge_value(conf->response, prev->response, 0);
    ngx_conf_merge_size_value(conf->res_body_max, prev->res_body_max,
                              64 * 1024);
    ngx_conf_merge_ptr_value(conf->cache_key, prev->cache_key, NULL);

    /* resolve group name → group pointer */
    if (conf->enable && conf->group_name.len) {
        mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_xngin_module);

        if (mmcf->groups) {
            ngx_http_xngin_group_t *g = mmcf->groups->elts;

            for (i = 0; i < mmcf->groups->nelts; i++) {
                if (g[i].name.len == conf->group_name.len
                    && ngx_memcmp(g[i].name.data, conf->group_name.data,
                                  conf->group_name.len) == 0)
                {
                    conf->group = &g[i];
                    break;
                }
            }
        }

        if (conf->group == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xngin: unknown agent group \"%V\"",
                               &conf->group_name);
            return NGX_CONF_ERROR;
        }
    }

    /* ensure bodies up to body_max stay in a single in-memory buffer */
    if (conf->body_inspect) {
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

        if ((size_t) clcf->client_body_buffer_size < conf->body_max) {
            clcf->client_body_buffer_size = (ssize_t) conf->body_max;
        }
    }

    return NGX_CONF_OK;
}


/* ---------- directive handlers ---------- */

static char *
ngx_http_xngin_agent_group(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xngin_main_conf_t *mmcf = conf;
    ngx_http_xngin_group_t     *g;
    ngx_str_t                  *value;
    ngx_conf_t                  save;
    ngx_uint_t                  i;
    char                       *rv;

    if (mmcf->groups == NULL) {
        mmcf->groups = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_http_xngin_group_t));
        if (mmcf->groups == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    /* duplicate name check */
    g = mmcf->groups->elts;
    for (i = 0; i < mmcf->groups->nelts; i++) {
        if (g[i].name.len == value[1].len
            && ngx_memcmp(g[i].name.data, value[1].data, value[1].len) == 0)
        {
            return "duplicate xngin agent group";
        }
    }

    g = ngx_array_push(mmcf->groups);
    if (g == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(g, sizeof(ngx_http_xngin_group_t));
    g->name = value[1];
    g->keepalive = 2;
    g->ping_interval = 10000;
    g->max_streams = XNAP_DEFAULT_MAX_STREAM;

    if (ngx_array_init(&g->agents, cf->pool, 4,
                       sizeof(ngx_http_xngin_agent_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    save = *cf;
    cf->handler = ngx_http_xngin_agent_conf;
    cf->handler_conf = g;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (g->agents.nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xngin: agent group \"%V\" has no servers",
                           &g->name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_xngin_agent_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xngin_group_t *g = cf->handler_conf;
    ngx_str_t              *value = cf->args->elts;
    ngx_http_xngin_agent_t *a;
    ngx_url_t               u;
    ngx_uint_t              i;

    if (cf->args->nelts < 2) {
        return "invalid number of arguments";
    }

    if (ngx_strcmp(value[0].data, "server") == 0) {
        a = ngx_array_push(&g->agents);
        if (a == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(a, sizeof(ngx_http_xngin_agent_t));
        a->weight = 1;
        a->group = g;
        a->url_text = value[1];

        ngx_memzero(&u, sizeof(ngx_url_t));
        u.url = value[1];
        u.no_resolve = 0;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
            if (u.err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "xngin: %s in server \"%V\"",
                                   u.err, &value[1]);
            }
            return NGX_CONF_ERROR;
        }

        if (u.naddrs) {
            a->addr = u.addrs[0];
        } else if (u.family == AF_UNIX) {
            /* unix socket path: sockaddr lives inside the stack url,
               copy it into the config pool */
            a->addr.sockaddr = ngx_palloc(cf->pool, u.socklen);
            if (a->addr.sockaddr == NULL) {
                return NGX_CONF_ERROR;
            }
            ngx_memcpy(a->addr.sockaddr, &u.sockaddr, u.socklen);
            a->addr.socklen = u.socklen;
            a->addr.name = u.url;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xngin: cannot resolve server \"%V\"",
                               &value[1]);
            return NGX_CONF_ERROR;
        }

        for (i = 2; i < cf->args->nelts; i++) {
            if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {
                a->weight = ngx_atoi(value[i].data + 7,
                                     value[i].len - 7);
                if (a->weight == (ngx_uint_t) NGX_ERROR || a->weight == 0) {
                    return "invalid weight";
                }
            } else if (ngx_strncmp(value[i].data, "max_streams=", 12) == 0) {
                a->max_streams = ngx_atoi(value[i].data + 12,
                                          value[i].len - 12);
                if (a->max_streams == (ngx_uint_t) NGX_ERROR) {
                    return "invalid max_streams";
                }
            } else {
                return "invalid server parameter";
            }
        }

        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "keepalive") == 0) {
        g->keepalive = ngx_atoi(value[1].data, value[1].len);
        if (g->keepalive == (ngx_uint_t) NGX_ERROR || g->keepalive == 0
            || g->keepalive > 64)
        {
            return "invalid keepalive";
        }
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "ping_interval") == 0) {
        g->ping_interval = ngx_parse_time(&value[1], 0);
        if (g->ping_interval == (ngx_msec_t) NGX_ERROR
            || g->ping_interval < 1000)
        {
            return "invalid ping_interval";
        }
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "max_streams") == 0) {
        g->max_streams = ngx_atoi(value[1].data, value[1].len);
        if (g->max_streams == (ngx_uint_t) NGX_ERROR || g->max_streams == 0) {
            return "invalid max_streams";
        }
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "xngin: invalid directive \"%V\" in agent group",
                       &value[0]);
    return NGX_CONF_ERROR;
}


static char *
ngx_http_xngin_cache_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xngin_main_conf_t *mmcf = conf;
    ngx_str_t                  *value, name, s;
    ssize_t                     size;
    u_char                     *p;

    if (mmcf->cache_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

    /* arg form: name:size  e.g. xngin_cache_zone verdicts:8m */
    p = ngx_strlchr(value[1].data, value[1].data + value[1].len, ':');
    if (p == NULL) {
        return "expected name:size";
    }

    name.data = value[1].data;
    name.len = p - value[1].data;

    s.data = p + 1;
    s.len = value[1].data + value[1].len - (p + 1);

    size = ngx_parse_size(&s);
    if (size == NGX_ERROR || size < 81920) {
        return "invalid zone size (min 80k)";
    }

    mmcf->cache_zone = ngx_shared_memory_add(cf, &name, size,
                                             &ngx_http_xngin_module);
    if (mmcf->cache_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    mmcf->cache_zone->init = ngx_http_xngin_cache_zone_init;
    mmcf->cache_zone->data = NULL;

    return NGX_CONF_OK;
}


static char *
ngx_http_xngin_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xngin_loc_conf_t *lcf = conf;
    ngx_str_t                 *value = cf->args->elts;

    if (lcf->mode != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "blocking") == 0) {
        lcf->mode = XNAP_MODE_BLOCKING;
    } else if (ngx_strcmp(value[1].data, "async") == 0) {
        lcf->mode = XNAP_MODE_ASYNC;
    } else {
        return "expected blocking|async";
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_xngin_fail_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xngin_loc_conf_t *lcf = conf;
    ngx_str_t                 *value = cf->args->elts;

    if (lcf->fail != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "open") == 0) {
        lcf->fail = XNAP_FAIL_OPEN;
    } else if (ngx_strcmp(value[1].data, "close") == 0) {
        lcf->fail = XNAP_FAIL_CLOSE;
    } else {
        return "expected open|close";
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_xngin_cache_key_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xngin_loc_conf_t       *lcf = conf;
    ngx_str_t                       *value = cf->args->elts;
    ngx_http_compile_complex_value_t ccv;

    if (lcf->cache_key != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    lcf->cache_key = ngx_palloc(cf->pool,
                              sizeof(ngx_http_complex_value_t));
    if (lcf->cache_key == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = lcf->cache_key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_xngin_tls_deny_add(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xngin_srv_conf_t *xscf = conf;
    ngx_str_t                 *value, *d;

    value = cf->args->elts;

    /* JA4 canonical form: a(10) '_' b(12) '_' c(12) = 36 chars */
    if (value[1].len != 36 || value[1].data[10] != '_'
        || value[1].data[23] != '_')
    {
        return "expected a 36-char JA4 fingerprint (a_b_c)";
    }

    if (xscf->tls_deny == NULL) {
        xscf->tls_deny = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (xscf->tls_deny == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    d = ngx_array_push(xscf->tls_deny);
    if (d == NULL) {
        return NGX_CONF_ERROR;
    }

    *d = value[1];

    return NGX_CONF_OK;
}


/* ---------- init ---------- */

static ngx_int_t
ngx_http_xngin_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt       *h;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_variable_t       *v, *nv;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_xngin_handler;

    ngx_http_xngin_filters_init();

    for (v = ngx_http_xngin_vars; v->name.len; v++) {
        nv = ngx_http_add_variable(cf, &v->name, v->flags);
        if (nv == NULL) {
            return NGX_ERROR;
        }
        nv->get_handler = v->get_handler;
        nv->data = v->data;
    }

    if (ngx_http_xngin_tls_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_init_process(ngx_cycle_t *cycle)
{
    ngx_http_xngin_main_conf_t *mmcf;

    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;
    }

    mmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_xngin_module);
    if (mmcf == NULL) {
        return NGX_OK;
    }

    return ngx_http_xngin_conn_init_worker(mmcf, cycle);
}


static void
ngx_http_xngin_exit_process(ngx_cycle_t *cycle)
{
    ngx_http_xngin_main_conf_t *mmcf;

    mmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_xngin_module);
    if (mmcf == NULL) {
        return;
    }

    ngx_http_xngin_conn_free_worker(mmcf, cycle);
}


/* ---------- request context / cleanup ---------- */

static void
ngx_http_xngin_req_cleanup(void *data)
{
    ngx_http_xngin_ctx_t *ctx = data;

    ngx_http_xngin_ctx_abort(ctx);
}


/* ---------- phase handler ---------- */

static ngx_int_t
ngx_http_xngin_handler(ngx_http_request_t *r)
{
    ngx_http_xngin_loc_conf_t  *lcf;
    ngx_http_xngin_ctx_t       *ctx;
    ngx_http_cleanup_t         *cln;
    ngx_int_t                   rc;
    ngx_str_t                   key;
    ngx_int_t                   cstatus;
    int64_t                     cscore;
    ngx_str_t                   creason;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xngin_module);

    if (!lcf->enable || lcf->group == NULL) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_xngin_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_xngin_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ctx->r = r;
        ctx->async = (lcf->mode == XNAP_MODE_ASYNC);
        ctx->cache_status = XNAP_CACHE_BYPASS;

        ctx->timer = ngx_pcalloc(r->pool, sizeof(ngx_event_t));
        ctx->timer->handler = ngx_http_xngin_timeout;
        ctx->timer->data = ctx;
        ctx->timer->log = r->connection->log;

        cln = ngx_http_cleanup_add(r, 0);
        if (cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        cln->handler = ngx_http_xngin_req_cleanup;
        cln->data = ctx;

        ngx_http_set_ctx(r, ctx, ngx_http_xngin_module);
    }

    /* resumed after verdict/timeout: return stored rc */
    if (ctx->state == XNAP_ST_DONE) {
        return ctx->status;
    }

    /* already dispatched, awaiting verdict (or fire-and-forget) */
    if (ctx->dispatched) {
        return ctx->async ? NGX_DECLINED : NGX_DONE;
    }

    /* engine-side verdict cache */
    if (lcf->cache_key && lcf->cache_key != NGX_CONF_UNSET_PTR) {
        if (ngx_http_complex_value(r, lcf->cache_key, &key) == NGX_OK
            && key.len)
        {
            ctx->cache_key_val = key;

            rc = ngx_http_xngin_cache_lookup(r, ctx, &key,
                                             &cstatus, &cscore, &creason);
            if (rc == NGX_OK) {
                ctx->score = cscore;
                ctx->reason = creason;
                if (cstatus == NGX_DECLINED) {
                    ngx_str_set(&ctx->action, "allow");
                } else {
                    ngx_str_set(&ctx->action, "deny");
                    ctx->deny_status = cstatus;
                }
                return cstatus;
            }
        }
    }

    /* optional body capture */
    if (lcf->body_inspect && !ctx->body_read
        && r->headers_in.content_length_n > 0
        && r->headers_in.content_length_n <= (off_t) lcf->body_max
        && r->request_body == NULL)
    {
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 0;
        r->request_body_in_clean_file = 0;

        ctx->in_handler = 1;
        rc = ngx_http_read_client_request_body(r, ngx_http_xngin_body_post);
        ctx->in_handler = 0;

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        /*
         * Body post handler semantics: it IS the continuation — the
         * machinery never re-enters phases.  For NGX_OK the post handler
         * already ran inline (dispatch may have happened); for
         * NGX_DONE/AGAIN the read completes later and the post handler
         * drives resumption itself.  Either way the outcome now lives in
         * ctx: decide the return code from it.
         */
        if (ctx->state == XNAP_ST_DONE) {
            rc = ctx->status;         /* dispatch failed inline */
        } else if (ctx->async) {
            rc = NGX_DECLINED;        /* async dispatched inline */
        } else {
            rc = NGX_DONE;            /* suspended: body read or verdict */
        }

        /*
         * ngx_http_read_client_request_body() takes a request reference
         * that stock callers get released when the content-phase checker
         * finalizes NGX_DONE.  The access-phase checker does not finalize
         * NGX_DONE — our handler is re-entered on the verdict path
         * instead — so release the reference here or the request ends
         * with count 2, keepalive never re-arms, and the next request on
         * this connection stalls in test_reading.
         */
        r->main->count--;

        return rc;
    }

    ctx->body_read = 1;

    ngx_http_xngin_launch(r, ctx, lcf);

    if (ctx->state == XNAP_ST_DONE) {
        return ctx->status;
    }

    return ctx->async ? NGX_DECLINED : NGX_DONE;
}


/* dispatch + suspend bookkeeping shared by phase handler and body post */
static void
ngx_http_xngin_launch(ngx_http_request_t *r, ngx_http_xngin_ctx_t *ctx,
    ngx_http_xngin_loc_conf_t *lcf)
{
    ngx_int_t rc;

    ctx->dispatched = 1;

    if (!ctx->async) {
        r->main->count++;
    }

    rc = ngx_http_xngin_dispatch(r, ctx);

    if (rc != NGX_OK) {
        if (!ctx->async) {
            r->main->count--;
        }

        ngx_str_set(&ctx->error, "down");
        ctx->cache_status = XNAP_CACHE_BYPASS;
        ctx->state = XNAP_ST_DONE;
        ctx->status = (ctx->async || lcf->fail == XNAP_FAIL_OPEN)
                      ? NGX_DECLINED
                      : NGX_HTTP_SERVICE_UNAVAILABLE;
        return;
    }

    if (!ctx->async) {
        ngx_add_timer(ctx->timer, lcf->timeout);
        r->read_event_handler = ngx_http_test_reading;
    }
}


static void
ngx_http_xngin_body_post(ngx_http_request_t *r)
{
    ngx_http_xngin_ctx_t     *ctx;
    ngx_http_xngin_loc_conf_t *lcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xngin_module);
    if (ctx == NULL) {
        return;
    }

    ctx->body_read = 1;
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xngin_module);

    ngx_http_xngin_launch(r, ctx, lcf);

    if (ctx->in_handler) {
        /* invoked inline inside the phase handler; the handler picks up
           ctx state and returns the right code — no re-entrant run_phases */
        return;
    }

    /* invoked from the body-read event: drive resumption where needed */
    if (ctx->async || ctx->state == XNAP_ST_DONE) {
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
    }
    /* blocking && SENT: suspended until the verdict arrives */
}


/* ---------- resume ---------- */

void
ngx_http_xngin_resume(ngx_http_request_t *r, ngx_int_t status)
{
    ngx_http_xngin_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xngin_module);
    if (ctx == NULL) {
        return;
    }

    ctx->status = status;
    ctx->state = XNAP_ST_DONE;

    r->main->count--;
    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
}


/* ---------- variables ---------- */

static ngx_http_xngin_ctx_t *
ngx_http_xngin_get_ctx(ngx_http_request_t *r, ngx_http_variable_value_t *v)
{
    ngx_http_xngin_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xngin_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NULL;
    }

    return ctx;
}


static ngx_int_t
ngx_http_xngin_var_action(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_xngin_ctx_t *ctx = ngx_http_xngin_get_ctx(r, v);
    if (ctx == NULL || ctx->action.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }
    v->data = ctx->action.data;
    v->len = ctx->action.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_var_score(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_xngin_ctx_t *ctx = ngx_http_xngin_get_ctx(r, v);
    u_char *p;

    if (ctx == NULL) {
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", ctx->score) - p;
    v->data = p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_var_reason(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_xngin_ctx_t *ctx = ngx_http_xngin_get_ctx(r, v);
    if (ctx == NULL || ctx->reason.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }
    v->data = ctx->reason.data;
    v->len = ctx->reason.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_var_error(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_xngin_ctx_t *ctx = ngx_http_xngin_get_ctx(r, v);
    if (ctx == NULL || ctx->error.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }
    v->data = ctx->error.data;
    v->len = ctx->error.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_var_rtt(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_xngin_ctx_t *ctx = ngx_http_xngin_get_ctx(r, v);
    u_char *p;

    if (ctx == NULL || ctx->sent_at == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%M", ctx->agent_rtt * 1000) - p;
    v->data = p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_var_cache(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_xngin_ctx_t *ctx = ngx_http_xngin_get_ctx(r, v);
    static const char *names[] = {
        "disabled", "miss", "hit", "bypass"
    };
    ngx_str_t s;

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->cache_status > XNAP_CACHE_BYPASS) {
        v->not_found = 1;
        return NGX_OK;
    }

    s.data = (u_char *) names[ctx->cache_status];
    s.len = ngx_strlen(names[ctx->cache_status]);

    v->data = s.data;
    v->len = s.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_var_ja4(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_xngin_hello_t *hello;

    hello = ngx_http_xngin_tls_hello(r->connection);
    if (hello == NULL || hello->ja4.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = hello->ja4.data;
    v->len = hello->ja4.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_var_prefix(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t              *name = (ngx_str_t *) data;
    ngx_str_t               key;
    ngx_http_xngin_ctx_t   *ctx;
    ngx_http_xngin_var_t   *var;
    ngx_uint_t              i;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xngin_module);
    if (ctx == NULL || ctx->vars == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    key.data = name->data + sizeof("xngin_") - 1;
    key.len = name->len - (sizeof("xngin_") - 1);

    var = ctx->vars->elts;
    for (i = 0; i < ctx->vars->nelts; i++) {
        if (var[i].name.len == key.len
            && ngx_memcmp(var[i].name.data, key.data, key.len) == 0)
        {
            v->data = var[i].value.data;
            v->len = var[i].value.len;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            return NGX_OK;
        }
    }

    v->not_found = 1;
    return NGX_OK;
}
