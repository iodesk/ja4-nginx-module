/*
 * ngx_stream_ja4_module.c
 *
 * Stream (TCP/UDP) counterpart of the JA4 TLS fingerprint module.
 * It mirrors the HTTP module but uses the Stream SSL API to install the
 * OpenSSL message callback and expose the same `$ssl_ja4*` variables.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <ngx_event_openssl.h>
#include <ngx_stream_ssl_module.h>

#ifndef NGX_STREAM_SSL
#define NGX_STREAM_SSL 1
#endif

/* #if (NGX_STREAM_SSL) */

#include <openssl/ssl.h>

#include <ngx_http_ja4.h>
#include <ngx_http_ja4_tls_parser.h>
#include <ngx_http_ja4_tls_server_parser.h>

static ngx_int_t ngx_stream_ja4_add_variables(ngx_conf_t *cf);
static void *ngx_stream_ja4_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_ja4_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_stream_ja4_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
extern void
ngx_http_ja4_msg_callback(int write_p, int version,
    int content_type, const void *buf, size_t len,
    ngx_ssl_conn_t *ssl, void *arg);

static ngx_stream_module_t  ngx_stream_ja4_module_ctx = {
    ngx_stream_ja4_add_variables,   /* preconfiguration */
    NULL,                           /* postconfiguration */

    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */

    ngx_stream_ja4_create_srv_conf, /* create server configuration */
    ngx_stream_ja4_merge_srv_conf   /* merge server configuration */
};

static ngx_command_t  ngx_stream_ja4_commands[] = {
    { ngx_string("ja4_stream_enable"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_http_ja4_srv_conf_t, enable),
      NULL },

    { ngx_string("ja4_stream_debug_enable"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_http_ja4_srv_conf_t, debug_enable),
      NULL },

    ngx_null_command
};

ngx_module_t  ngx_stream_ja4_module = {
    NGX_MODULE_V1,
    &ngx_stream_ja4_module_ctx,    /* module context */
    ngx_stream_ja4_commands,       /* module directives */
    NGX_STREAM_MODULE,             /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_stream_variable_t  ngx_stream_ja4_variables[] = {
    { ngx_string("ssl_ja4"), NULL, ngx_stream_ja4_variable,
      0, NGX_STREAM_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_ja4s"), NULL, ngx_stream_ja4_variable,
      3, NGX_STREAM_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_ja4_r"), NULL, ngx_stream_ja4_variable,
      1, NGX_STREAM_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_ja4_o"), NULL, ngx_stream_ja4_variable,
      2, NGX_STREAM_VAR_NOCACHEABLE, 0 },

    ngx_stream_null_variable
};

static ngx_int_t
ngx_stream_ja4_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_ja4_variables; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        *var = *v;
    }
    return NGX_OK;
}

static void *
ngx_stream_ja4_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ja4_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ja4_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enable = NGX_CONF_UNSET;
    conf->debug_enable = NGX_CONF_UNSET;
    return conf;
}

static char *
ngx_stream_ja4_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ja4_srv_conf_t *prev = parent;
    ngx_http_ja4_srv_conf_t *conf = child;
    ngx_stream_ssl_srv_conf_t *sscf;
    SSL_CTX *ctx;

    ngx_conf_merge_value(conf->enable, prev->enable, 1);
    ngx_conf_merge_value(conf->debug_enable, prev->debug_enable, 0);

    if (!conf->enable) {
        return NGX_CONF_OK;
    }

    sscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_ssl_module);
    if (sscf == NULL || sscf->ssl.ctx == NULL) {
        return NGX_CONF_OK;
    }

    ctx = sscf->ssl.ctx;

    SSL_CTX_set_msg_callback(ctx,
        (void (*)(int,int,int,const void *,size_t,SSL *,void *))
        ngx_http_ja4_msg_callback);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_stream_ja4_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_connection_t        *c;
    ngx_http_ja4_ctx_t      *ctx;
    ngx_http_ja4_srv_conf_t *scf;
    u_char                  *out;
    size_t                   out_len;

    v->not_found = 1;

    c = s->connection;
    if (c == NULL || c->ssl == NULL || c->ssl->connection == NULL) {
        return NGX_OK;
    }

    scf = ngx_stream_get_module_srv_conf(s, ngx_stream_ja4_module);
    if (scf == NULL || !scf->enable) {
        return NGX_OK;
    }

    if ((data == 1 || data == 2) && !scf->debug_enable) {
        return NGX_OK;
    }

    ctx = SSL_get_ex_data(c->ssl->connection, ngx_http_ja4_ssl_index);
    if (ctx == NULL || !ctx->done) {
        return NGX_OK;
    }

    switch (data) {
    case 1:
        out = ctx->ja4_r;
        out_len = ctx->ja4_r_len;
        break;
    case 2:
        out = ctx->ja4_o;
        out_len = ctx->ja4_o_len;
        break;
    case 3:
        out = ctx->ja4s;
        out_len = ctx->ja4s_len;
        break;
    default:
        out = ctx->ja4;
        out_len = ctx->ja4_len;
        break;
    }

    if (out_len == 0) {
        return NGX_OK;
    }

    v->data = out;
    v->len = out_len;
    v->valid = 1;
    v->not_found = 0;
    v->no_cacheable = 1;

    return NGX_OK;
}

/* The actual TLS parsing / fingerprint code lives in the shared
 * `ngx_http_ja4_*` files and is invoked via the OpenSSL callback set
 * above.  No further stream-specific logic is required here. */

/* #endif */
