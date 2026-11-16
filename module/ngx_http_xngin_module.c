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
static char *ngx_http_xngin_ban_zone_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_group_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_mode(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_fail_mode(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_cache_key_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_tls_deny_add(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_var_add(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_header_add(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_status_loc(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xngin_group_ssl(ngx_conf_t *cf,
    ngx_http_xngin_group_t *g);
static char *ngx_http_xngin_group_arg(ngx_conf_t *cf, ngx_str_t *field,
    ngx_uint_t ispath);


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
static ngx_int_t ngx_http_xngin_var_us(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_xngin_var_cache(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_xngin_var_ja4(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_xngin_var_prefix(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_xngin_var_agent(ngx_http_request_t *r,
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

    { ngx_string("xngin_ban_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_xngin_ban_zone_set,
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
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_xngin_group_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xngin_response_group"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, response_group_name),
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

    { ngx_string("xngin_body_replace"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, body_replace),
      NULL },

    { ngx_string("xngin_upload_drain"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, upload_drain),
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

    { ngx_string("xngin_var"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_xngin_var_add,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xngin_header_include"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_xngin_header_add,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, hdr_include),
      NULL },

    { ngx_string("xngin_internal"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, internal_req),
      NULL },

    { ngx_string("xngin_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_xngin_status_loc,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xngin_header_exclude"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_xngin_header_add,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xngin_loc_conf_t, hdr_exclude),
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

    { ngx_string("xngin_encode_us"), NULL,
      ngx_http_xngin_var_us, offsetof(ngx_http_xngin_ctx_t, enc_us),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("xngin_syscall_us"), NULL,
      ngx_http_xngin_var_us, offsetof(ngx_http_xngin_ctx_t, sys_us),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("xngin_agent_us"), NULL,
      ngx_http_xngin_var_us, offsetof(ngx_http_xngin_ctx_t, agent_us),
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("xngin_cache"), NULL,
      ngx_http_xngin_var_cache, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("xngin_ja4"), NULL,
      ngx_http_xngin_var_ja4, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("xngin_agent"), NULL,
      ngx_http_xngin_var_agent, 0,
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
    lcf->body_replace = NGX_CONF_UNSET;
    lcf->upload_drain = NGX_CONF_UNSET;
    lcf->response = NGX_CONF_UNSET;
    lcf->res_body_max = NGX_CONF_UNSET_SIZE;
    lcf->cache_key = NGX_CONF_UNSET_PTR;
    lcf->internal_req = NGX_CONF_UNSET;

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
    ngx_conf_merge_value(conf->body_replace, prev->body_replace, 1);
    ngx_conf_merge_value(conf->upload_drain, prev->upload_drain, 1);
    ngx_conf_merge_value(conf->response, prev->response, 0);
    ngx_conf_merge_size_value(conf->res_body_max, prev->res_body_max,
                              64 * 1024);
    ngx_conf_merge_ptr_value(conf->cache_key, prev->cache_key, NULL);

    if (conf->vars == NULL) {
        conf->vars = prev->vars;
    }
    if (conf->hdr_include == NULL) {
        conf->hdr_include = prev->hdr_include;
    }
    if (conf->hdr_exclude == NULL) {
        conf->hdr_exclude = prev->hdr_exclude;
    }
    ngx_conf_merge_value(conf->internal_req, prev->internal_req, 1);
    ngx_conf_merge_ptr_value(conf->steps, prev->steps, NULL);
    ngx_conf_merge_str_value(conf->response_group_name,
                             prev->response_group_name, "");

    /* resolve group names → group pointers */
    if (conf->enable && conf->steps) {
        ngx_http_xngin_step_t   *st = conf->steps->elts;
        ngx_http_xngin_group_t  *g = NULL;
        ngx_uint_t               s;

        mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_xngin_module);
        if (mmcf->groups) {
            g = mmcf->groups->elts;
        }

        for (s = 0; s < conf->steps->nelts; s++) {
            st[s].group = NULL;
            if (g) {
                for (i = 0; i < mmcf->groups->nelts; i++) {
                    if (g[i].name.len == st[s].group_name.len
                        && ngx_memcmp(g[i].name.data, st[s].group_name.data,
                                      st[s].group_name.len) == 0)
                    {
                        st[s].group = &g[i];
                        break;
                    }
                }
            }
            if (st[s].group == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "xngin: unknown agent group \"%V\"",
                                   &st[s].group_name);
                return NGX_CONF_ERROR;
            }

            /* "server ... resolve" uses the resolver effective where
               the group is referenced — a resolver in server{} or
               location{} lands on this loc conf via merge, not on the
               http-level conf ngx_http_xngin_init can see */
            clcf = ngx_http_conf_get_module_loc_conf(cf,
                                                     ngx_http_core_module);
            if (clcf->resolver && clcf->resolver->connections.nelts
                && (st[s].group->resolver == NULL
                    || st[s].group->resolver->connections.nelts == 0))
            {
                st[s].group->resolver = clcf->resolver;
            }
        }

        /* groups the CONTROL bans of these steps can affect */
        conf->groups = ngx_array_create(cf->pool, conf->steps->nelts,
                                        sizeof(ngx_http_xngin_group_t *));
        if (conf->groups == NULL) {
            return NGX_CONF_ERROR;
        }
        for (s = 0; s < conf->steps->nelts; s++) {
            ngx_http_xngin_group_t **gp = ngx_array_push(conf->groups);
            if (gp == NULL) {
                return NGX_CONF_ERROR;
            }
            *gp = st[s].group;
        }

        conf->group = st[0].group;
        conf->group_name = st[0].group_name;

        /* xngin_response_group: which group's agents see responses */
        if (conf->response_group_name.len) {
            conf->response_group = NULL;
            if (g) {
                for (i = 0; i < mmcf->groups->nelts; i++) {
                    if (g[i].name.len == conf->response_group_name.len
                        && ngx_memcmp(g[i].name.data,
                                      conf->response_group_name.data,
                                      conf->response_group_name.len) == 0)
                    {
                        conf->response_group = &g[i];
                        break;
                    }
                }
            }
            if (conf->response_group == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "xngin: unknown agent group \"%V\"",
                                   &conf->response_group_name);
                return NGX_CONF_ERROR;
            }
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
    g->resolve_interval = 30000;

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

    return ngx_http_xngin_group_ssl(cf, g);
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

        /* pre-scan: "resolve" tolerates names that don't resolve at
           config load (k8s Service etc.) */
        for (i = 2; i < cf->args->nelts; i++) {
            if (ngx_strcmp(value[i].data, "resolve") == 0) {
                a->resolve = 1;
            }
        }

        ngx_memzero(&u, sizeof(ngx_url_t));
        u.url = value[1];
        u.no_resolve = 0;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
            if (a->resolve && u.err
                && ngx_strstr(u.err, "host not found"))
            {
                u.naddrs = 0;
            } else {
                if (u.err) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "xngin: %s in server \"%V\"",
                                       u.err, &value[1]);
                }
                return NGX_CONF_ERROR;
            }
        }

        if (a->resolve) {
            if (u.family == AF_UNIX) {
                return "resolve not allowed for unix socket";
            }
            a->host = u.host;
            a->port = u.port;
            g->has_resolve = 1;
        }

        if (u.naddrs) {
            a->naddrs = ngx_min(u.naddrs, XNAP_MAX_ADDRS);
            for (i = 0; i < a->naddrs; i++) {
                if (u.addrs[i].socklen
                    > sizeof(struct sockaddr_storage))
                {
                    a->naddrs = i;
                    break;
                }
                ngx_memcpy(&a->ss[i], u.addrs[i].sockaddr,
                           u.addrs[i].socklen);
                a->addrs[i].sockaddr = (struct sockaddr *) &a->ss[i];
                a->addrs[i].socklen = u.addrs[i].socklen;
                a->addrs[i].name = a->url_text;
            }
            a->addr = a->addrs[0];
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
        } else if (!a->resolve) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xngin: cannot resolve server \"%V\"",
                               &value[1]);
            return NGX_CONF_ERROR;
        }
        /* else: resolve with 0 addrs — first DNS refresh fills them in */

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
            } else if (ngx_strcmp(value[i].data, "backup") == 0) {
                a->backup = 1;
            } else if (ngx_strcmp(value[i].data, "resolve") == 0) {
                /* handled in pre-scan */
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

    if (ngx_strcmp(value[0].data, "balance") == 0) {
        ngx_http_compile_complex_value_t  ccv;

        if (cf->args->nelts != 3
            || ngx_strcmp(value[1].data, "hash") != 0)
        {
            return "expected \"balance hash <value>\"";
        }
        if (g->balance_cv) {
            return "is duplicate";
        }
        g->balance_cv = ngx_palloc(cf->pool,
                                 sizeof(ngx_http_complex_value_t));
        if (g->balance_cv == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &value[2];
        ccv.complex_value = g->balance_cv;
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "resolve_interval") == 0) {
        g->resolve_interval = ngx_parse_time(&value[1], 0);
        if (g->resolve_interval == (ngx_msec_t) NGX_ERROR
            || g->resolve_interval < 5000)
        {
            return "invalid resolve_interval";
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

    if (ngx_strcmp(value[0].data, "ssl") == 0) {
        if (cf->args->nelts != 2
            || ngx_strcmp(value[1].data, "on") != 0)
        {
            return "expected \"ssl on\"";
        }
        g->ssl_on = 1;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[0].data, "ssl_certificate") == 0) {
        return ngx_http_xngin_group_arg(cf, &g->ssl_cert, 1);
    }

    if (ngx_strcmp(value[0].data, "ssl_certificate_key") == 0) {
        return ngx_http_xngin_group_arg(cf, &g->ssl_key, 1);
    }

    if (ngx_strcmp(value[0].data, "ssl_trusted_certificate") == 0) {
        return ngx_http_xngin_group_arg(cf, &g->ssl_trusted, 1);
    }

    if (ngx_strcmp(value[0].data, "ssl_server_name") == 0) {
        return ngx_http_xngin_group_arg(cf, &g->ssl_server_name, 0);
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "xngin: invalid directive \"%V\" in agent group",
                       &value[0]);
    return NGX_CONF_ERROR;
}


/* single-argument group directive; ispath resolves relative to prefix */
static char *
ngx_http_xngin_group_arg(ngx_conf_t *cf, ngx_str_t *field, ngx_uint_t ispath)
{
    ngx_str_t *value = cf->args->elts;

    if (cf->args->nelts != 2) {
        return "invalid number of arguments";
    }
    if (field->len) {
        return "is duplicate";
    }

    *field = value[1];
    if (ispath
        && ngx_conf_full_name(cf->cycle, field, 1) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


#if (NGX_SSL)

/* finalize an agent group's mTLS ctx: engine is the TLS client and must
   verify the agent cert (ssl_trusted_certificate is mandatory); a
   configured ssl_certificate/key turns it into mutual TLS */
static char *
ngx_http_xngin_group_ssl(ngx_conf_t *cf, ngx_http_xngin_group_t *g)
{
    ngx_ssl_t *ssl;

    if (!g->ssl_on) {
        if (g->ssl_cert.len || g->ssl_key.len || g->ssl_trusted.len
            || g->ssl_server_name.len)
        {
            return "ssl_* directives require \"ssl on\"";
        }
        return NGX_CONF_OK;
    }

    if (!g->ssl_trusted.len) {
        return "\"ssl on\" requires ssl_trusted_certificate";
    }

    ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (ssl == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_create(ssl, NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3, cf->log)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (g->ssl_cert.len) {
        if (!g->ssl_key.len) {
            return "ssl_certificate requires ssl_certificate_key";
        }
        if (ngx_ssl_certificate(cf, ssl, &g->ssl_cert, &g->ssl_key, NULL)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

    } else if (g->ssl_key.len) {
        return "ssl_certificate_key requires ssl_certificate";
    }

    if (ngx_ssl_trusted_certificate(cf, ssl, &g->ssl_trusted, 1)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* client mode: handshake must fail on an unverifiable agent cert */
    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, NULL);

    g->ssl = ssl;
    return NGX_CONF_OK;
}

#else  /* !(NGX_SSL) */

static char *
ngx_http_xngin_group_ssl(ngx_conf_t *cf, ngx_http_xngin_group_t *g)
{
    if (g->ssl_on || g->ssl_cert.len || g->ssl_key.len
        || g->ssl_trusted.len || g->ssl_server_name.len)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xngin: ssl directives require nginx built "
                           "--with-http_ssl_module");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

#endif


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
ngx_http_xngin_ban_zone_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xngin_main_conf_t *mmcf = conf;
    ngx_str_t                  *value, name, s;
    ssize_t                     size;
    u_char                     *p;

    if (mmcf->ban_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

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

    mmcf->ban_zone = ngx_shared_memory_add(cf, &name, size,
                                           &ngx_http_xngin_module);
    if (mmcf->ban_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    mmcf->ban_zone->init = ngx_http_xngin_ban_zone_init;
    mmcf->ban_zone->data = NULL;

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


/* xngin_group name [timeout=T] [fail=open|close] [mode=blocking|async]
   — repeatable: each line is one sequential step */
static char *
ngx_http_xngin_group_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xngin_loc_conf_t *lcf = conf;
    ngx_str_t                 *value = cf->args->elts;
    ngx_http_xngin_step_t     *st;
    ngx_uint_t                 i;
    ngx_msec_t                 msec;

    if (lcf->steps == NULL) {
        lcf->steps = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_http_xngin_step_t));
        if (lcf->steps == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    st = ngx_array_push(lcf->steps);
    if (st == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(st, sizeof(ngx_http_xngin_step_t));
    st->group_name = value[1];
    st->timeout = NGX_CONF_UNSET_MSEC;
    st->fail = NGX_CONF_UNSET_UINT;
    st->mode = NGX_CONF_UNSET_UINT;

    for (i = 2; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            value[i].data += 8;
            value[i].len -= 8;
            msec = ngx_parse_time(&value[i], 0);
            if (msec == (ngx_msec_t) NGX_ERROR) {
                return "invalid step timeout";
            }
            st->timeout = msec;
        } else if (ngx_strncmp(value[i].data, "fail=", 5) == 0) {
            if (ngx_strcmp(value[i].data + 5, "open") == 0) {
                st->fail = XNAP_FAIL_OPEN;
            } else if (ngx_strcmp(value[i].data + 5, "close") == 0) {
                st->fail = XNAP_FAIL_CLOSE;
            } else {
                return "expected fail=open|close";
            }
        } else if (ngx_strncmp(value[i].data, "mode=", 5) == 0) {
            if (ngx_strcmp(value[i].data + 5, "blocking") == 0) {
                st->mode = XNAP_MODE_BLOCKING;
            } else if (ngx_strcmp(value[i].data + 5, "async") == 0) {
                st->mode = XNAP_MODE_ASYNC;
            } else {
                return "expected mode=blocking|async";
            }
        } else {
            return "invalid step parameter";
        }
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


/* xngin_var <name> <complex value>: extra KV pairs the NOTIFY carries —
   lets operators forward nginx variables (client cert DN, GeoIP, userid,
   session data) that the agent can't otherwise see */
static char *
ngx_http_xngin_var_add(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xngin_loc_conf_t       *lcf = conf;
    ngx_str_t                       *value;
    ngx_http_xngin_named_cv_t       *v;
    ngx_http_compile_complex_value_t ccv;

    value = cf->args->elts;

    if (value[1].len == 0) {
        return "empty variable name";
    }

    if (lcf->vars == NULL) {
        lcf->vars = ngx_array_create(cf->pool, 4,
                                     sizeof(ngx_http_xngin_named_cv_t));
        if (lcf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    v = ngx_array_push(lcf->vars);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    v->name = value[1];
    v->cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (v->cv == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = v->cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* xngin_header_include/exclude <name>: allowlist for request/response
   headers forwarded to the agent (Cookie/Authorization hygiene) */
static char *
ngx_http_xngin_header_add(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xngin_loc_conf_t *lcf = conf;
    ngx_str_t                 *value, *f;
    ngx_array_t              **a;

    value = cf->args->elts;

    if (value[1].len == 0) {
        return "empty header name";
    }

    a = (ngx_array_t **) ((u_char *) lcf + cmd->offset);

    if (*a == NULL) {
        *a = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (*a == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    f = ngx_array_push(*a);
    if (f == NULL) {
        return NGX_CONF_ERROR;
    }

    f->len = value[1].len;
    f->data = ngx_pnalloc(cf->pool, value[1].len);
    if (f->data == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_strlow(f->data, value[1].data, value[1].len);

    return NGX_CONF_OK;
}


/* xngin_status: stub_status-style content handler */
static char *
ngx_http_xngin_status_loc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_xngin_status_handler;

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
    ngx_http_xngin_stream_filter_init();

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
    ngx_http_xngin_main_conf_t *mmcf;
    ngx_http_xngin_ctx_t       *ctx;
    ngx_http_cleanup_t         *cln;
    ngx_int_t                   rc;
    ngx_str_t                   key;
    ngx_int_t                   cstatus;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xngin_module);

    if (!lcf->enable || lcf->steps == NULL || lcf->steps->nelts == 0) {
        return NGX_DECLINED;
    }

    /* xngin_internal off: skip internal redirects and subrequests
       (auth_request double-counting a rate limiter, e.g.) */
    if (!lcf->internal_req && (r->internal || r != r->main)) {
        return NGX_DECLINED;
    }

    /* agent-pushed IP bans only bind groups this location consults */
    mmcf = ngx_http_get_module_main_conf(r, ngx_http_xngin_module);
    if (mmcf && lcf->groups
        && ngx_http_xngin_ban_check(mmcf, XNAP_BAN_IP,
                                    &r->connection->addr_text,
                                    lcf->groups))
    {
        return NGX_HTTP_FORBIDDEN;
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

    /*
     * Engine-side verdict cache.  Only consulted for single-step
     * locations: the entry replays one step's verdict, so on a chain it
     * would let a trailing group's cache-ttl skip every earlier group.
     */
    if (lcf->steps->nelts == 1
        && lcf->cache_key && lcf->cache_key != NGX_CONF_UNSET_PTR)
    {
        if (ngx_http_complex_value(r, lcf->cache_key, &key) == NGX_OK
            && key.len)
        {
            ctx->cache_key_val = key;

            /* the node identity is (group, key): only a verdict the
               location's own step group stored may replay here */
            rc = ngx_http_xngin_cache_lookup(r, ctx, &key,
                                             &lcf->group->name, &cstatus);
            if (rc == NGX_OK) {
                if (cstatus == NGX_DECLINED) {
                    ngx_str_set(&ctx->action, "allow");
                    return NGX_DECLINED;
                }
                ngx_str_set(&ctx->action, "deny");
                ctx->deny_status = cstatus;
                ctx->own_resp = 1;
                if (ctx->deny_body.len) {
                    /* cached deny carries its own body: proceed to the
                       content phase so deny_content can emit it */
                    r->content_handler = ngx_http_xngin_deny_content;
                    return NGX_DECLINED;
                }
                /* the unread client body must still be consumed or the
                   next keep-alive request desynchronizes */
                if (ngx_http_discard_request_body(r) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
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
        /* one contiguous capture buf is only needed when the agent may
           replace the body upstream; xngin_body_replace off also turns
           the streaming filter's zero-copy BODY frames into copies */
        if (lcf->body_replace) {
            r->request_body_in_single_buf = 1;
        }
        r->request_body_in_persistent_file = 0;
        r->request_body_in_clean_file = 0;

        /*
         * Early dispatch: the NOTIFY goes out before the upload is
         * buffered; BODY frames stream through the request body filter
         * as chunks arrive, overlapping the upload with agent analysis.
         * If dispatch fails inline (state DONE) the body is skipped
         * entirely — same as any other early deny.
         * Sequential groups can't stream: each step needs the whole
         * body, so the chain waits for the buffered read to finish.
         */
        if (lcf->steps->nelts == 1) {
            ctx->body_stream = 1;
            ctx->in_handler = 1;
            ngx_http_xngin_launch(r, ctx, lcf);
        }

        if (ctx->state == XNAP_ST_DONE) {
            ctx->body_stream = 0;
            ctx->in_handler = 0;
            return ctx->status;
        }

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
        } else if (rc == NGX_AGAIN || rc == NGX_DONE) {
            rc = NGX_DONE;            /* body read still in flight */
        } else if (ctx->async) {
            rc = NGX_DECLINED;        /* body consumed; fire-and-forget */
        } else {
            rc = NGX_DONE;            /* suspended: awaiting verdict */
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

/* walk the step chain from ctx->step: dispatch each step, skipping
   fail-open/async steps that can't block the request.  Returns 1 when
   suspended on a blocking step; 0 when the chain resolved inline
   (ctx->state DONE, ctx->status set — count ref NOT released, callers
   own it) */
ngx_int_t
ngx_http_xngin_advance(ngx_http_request_t *r, ngx_http_xngin_ctx_t *ctx,
    ngx_http_xngin_loc_conf_t *lcf)
{
    ngx_int_t rc;

    while (ctx->step < lcf->steps->nelts) {

        ctx->retried = 0;
        ctx->stream_failed = 0;
        ctx->async = (ngx_http_xngin_step_mode(lcf, ctx)
                      == XNAP_MODE_ASYNC);

        if (!ctx->async && !ctx->counted) {
            r->main->count++;
            ctx->counted = 1;
        }

        rc = ngx_http_xngin_dispatch(r, ctx);

        if (rc != NGX_OK) {
            ngx_str_set(&ctx->error, "down");
            ctx->cache_status = XNAP_CACHE_BYPASS;
            if (ctx->async
                || ngx_http_xngin_step_fail(lcf, ctx) == XNAP_FAIL_OPEN)
            {
                ctx->step++;   /* step can't block — move on */
                continue;
            }
            ctx->state = XNAP_ST_DONE;
            ctx->status = NGX_HTTP_SERVICE_UNAVAILABLE;
            return 0;
        }

        if (!ctx->async) {
            /*
             * Streaming dispatch: the verdict wait can't start until the
             * whole upload has been forwarded, so the verdict timer is
             * armed in body_post instead of here.  Body_post always runs
             * (read complete, or conn_failed/timeout defers there too).
             */
            if (!ctx->body_stream) {
                ngx_add_timer(ctx->timer,
                              ngx_http_xngin_step_timeout(lcf, ctx));
            }
            r->read_event_handler = ngx_http_test_reading;
            return 1;
        }

        ctx->step++;   /* async step: fire-and-forget, keep walking */
    }

    ctx->state = XNAP_ST_DONE;
    ctx->status = NGX_DECLINED;
    return 0;
}


static void
ngx_http_xngin_launch(ngx_http_request_t *r, ngx_http_xngin_ctx_t *ctx,
    ngx_http_xngin_loc_conf_t *lcf)
{
    ctx->dispatched = 1;

    if (!ngx_http_xngin_advance(r, ctx, lcf) && ctx->counted) {
        /* resolved inline — release the suspend ref */
        r->main->count--;
        ctx->counted = 0;
    }
}


static void
ngx_http_xngin_body_post(ngx_http_request_t *r)
{
    ngx_http_xngin_ctx_t     *ctx;
    ngx_http_xngin_loc_conf_t *lcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xngin_module);
    if (ctx == NULL || ctx->early_close) {
        return;
    }

    ctx->body_read = 1;
    ctx->body_stream = 0;
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xngin_module);

    if (ctx->req_body_set && ctx->state == XNAP_ST_DONE) {
        /* early verdict replaced the body while the upload was in
           flight; safe to swap rb->bufs now that the read is done */
        ngx_http_xngin_apply_req_body(r, ctx);
    }

    if (!ctx->dispatched) {
        ngx_http_xngin_launch(r, ctx, lcf);

    } else if (ctx->stream_failed) {
        /* the stream died mid-upload: apply the fail policy now that
           the request body has been fully consumed */
        ctx->state = XNAP_ST_DONE;
        ctx->status = (ctx->async
                      || ngx_http_xngin_step_fail(lcf, ctx) == XNAP_FAIL_OPEN)
                      ? NGX_DECLINED : NGX_HTTP_SERVICE_UNAVAILABLE;
        ngx_str_set(&ctx->error, "down");
        ctx->cache_status = XNAP_CACHE_BYPASS;
    }

    if (ctx->in_handler) {
        /* invoked inline inside the phase handler; the handler picks up
           ctx state and returns the right code — no re-entrant run_phases */
        return;
    }

    /* invoked from the body-read event: drive resumption where needed */
    if (ctx->async || ctx->state == XNAP_ST_DONE) {
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
        return;
    }

    /* blocking && SENT: suspended until the verdict arrives */
    if (ctx->dispatched) {
        r->read_event_handler = ngx_http_test_reading;
        if (!ctx->async && ctx->state == XNAP_ST_SENT
            && !ctx->timer->timer_set)
        {
            ngx_add_timer(ctx->timer,
                          ngx_http_xngin_step_timeout(lcf, ctx));
        }
    }
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

    /* the module is answering the request itself — the response it
       generates must not be offered to xngin_response inspection */
    if (status != NGX_DECLINED && status != NGX_DONE) {
        ctx->own_resp = 1;
    }

    if (ctx->counted) {
        r->main->count--;
        ctx->counted = 0;
    }

    if (!ctx->body_read) {
        if (!ctx->early_close) {
            /* early verdict while the upload is still streaming: stash
               the outcome; ngx_http_xngin_body_post resumes when the
               body read completes */
            return;
        }

        /*
         * xngin_upload_drain off: answer immediately and let the
         * connection close.  Stop BODY streaming, disarm the pending
         * body read (its count ref was already released in the
         * handler's first run), and force the same outcome finalize
         * derives for an in-flight unbuffered read: keepalive off +
         * lingering close → the response goes out, then the conn dies.
         */
        ctx->body_stream = 0;
        r->read_event_handler = ngx_http_test_reading;
        r->keepalive = 0;
        r->lingering_close = 1;
    }

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

    v->len = ngx_sprintf(p, "%L", ctx->agent_rtt) - p;
    v->data = p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


static ngx_int_t
ngx_http_xngin_var_us(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_xngin_ctx_t *ctx = ngx_http_xngin_get_ctx(r, v);
    int64_t             *field;
    u_char              *p;

    if (ctx == NULL || !ctx->dispatched) {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    field = (int64_t *) ((u_char *) ctx + data);

    v->len = ngx_sprintf(p, "%L", *field) - p;
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
ngx_http_xngin_var_agent(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_xngin_ctx_t *ctx = ngx_http_xngin_get_ctx(r, v);
    if (ctx == NULL || ctx->agent_name.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }
    v->data = ctx->agent_name.data;
    v->len = ctx->agent_name.len;
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
