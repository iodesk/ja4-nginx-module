/*
 * ngx_http_ja4_module.c
 *
 * JA4 TLS ClientHello fingerprint for nginx, as a standalone module.
 *
 * This file only handles nginx integration: module registration, directives,
 * variables, configuration and the OpenSSL message callback hook.  The TLS
 * parsing and fingerprint construction live in the dedicated layers
 * (ngx_http_ja4_parser.c / ngx_http_ja4_builder.c / ngx_http_ja4_crypto.c).
 *
 * No core nginx (or OpenSSL) modification required: the module installs an
 * OpenSSL message callback (SSL_CTX_set_msg_callback) on the per-server
 * SSL_CTX (the same one created by the standard http_ssl_module) and hands
 * the raw ClientHello to the parser.
 *
 * Variables: "$ssl_ja4", "$ssl_ja4_r" and "$ssl_ja4_o".
 *
 * JA4 spec:
 *   https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
 *
 * Build:
 *   ./configure --with-http_ssl_module \
 *       [--with-http_v3_module] --add-module=path/to/ja4
 *   (--with-http_v3_module enables QUIC/'q' detection; requires OpenSSL 3.x)
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_event_openssl.h>
#include <ngx_http_ssl_module.h>

#if (NGX_HTTP_SSL)

#include <openssl/ssl.h>

#include <ngx_http_ja4.h>
#include <ngx_http_ja4_tls_parser.h>
#include <ngx_http_ja4_tls_server_parser.h>
#include <ngx_http_ja4_http_parser.h>


int  ngx_http_ja4_ssl_index = -1;

static ngx_int_t ngx_http_ja4_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_ja4_add_variables(ngx_conf_t *cf);
static void *ngx_http_ja4_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ja4_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_ja4_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ja4h_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
void ngx_http_ja4_msg_callback(int write_p, int version,
    int content_type, const void *buf, size_t len, ngx_ssl_conn_t *ssl,
    void *arg);

static ngx_http_module_t  ngx_http_ja4_module_ctx = {
    ngx_http_ja4_add_variables,             /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_http_ja4_create_srv_conf,           /* create server configuration */
    ngx_http_ja4_merge_srv_conf,            /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};

static ngx_command_t  ngx_http_ja4_commands[] = {

    { ngx_string("ja4_enable"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ja4_srv_conf_t, enable),
      NULL },

    { ngx_string("ja4_debug_enable"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ja4_srv_conf_t, debug_enable),
      NULL },

      ngx_null_command
};

ngx_module_t  ngx_http_ja4_module = {
    NGX_MODULE_V1,
    &ngx_http_ja4_module_ctx,               /* module context */
    ngx_http_ja4_commands,                  /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    ngx_http_ja4_init_module,               /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t  ngx_http_ja4_variables[] = {

    /* always present */
    { ngx_string("ssl_ja4"), NULL, ngx_http_ja4_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("http_ja4h"), NULL, ngx_http_ja4h_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_ja4s"), NULL, ngx_http_ja4_variable,
      3, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    /* debug variables; return not_found unless ja4_debug_enable on */
    { ngx_string("ssl_ja4_r"), NULL, ngx_http_ja4_variable,
      1, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_ja4_o"), NULL, ngx_http_ja4_variable,
      2, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};

static ngx_int_t
ngx_http_ja4_init_module(ngx_cycle_t *cycle)
{
    long  index;

    if (ngx_http_ja4_ssl_index != -1) {
        return NGX_OK;
    }

    index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (index == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "ja4: SSL_get_ex_new_index() failed");
        return NGX_ERROR;
    }

    ngx_http_ja4_ssl_index = index;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ja4_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ja4_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        *var = *v;
    }

    return NGX_OK;
}

static void *
ngx_http_ja4_create_srv_conf(ngx_conf_t *cf)
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
ngx_http_ja4_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ja4_srv_conf_t  *prev = parent;
    ngx_http_ja4_srv_conf_t  *conf = child;
    ngx_http_ssl_srv_conf_t  *sscf;
    SSL_CTX                  *ctx;

    /*
     * Enabled by default; can be turned off per server with
     * "ja4_enable off".  One switch controls both the JA4 (TLS) and
     * JA4H (HTTP) pipelines.
     */
    ngx_conf_merge_value(conf->enable, prev->enable, 1);
    ngx_conf_merge_value(conf->debug_enable, prev->debug_enable, 0);

    if (!conf->enable) {
        return NGX_CONF_OK;
    }

    /*
     * Install the OpenSSL message callback on this server's SSL_CTX.
     * ngx_http_ssl_module is merged before addon modules (it appears
     * earlier in the module list), so its srv conf and SSL_CTX are
     * already prepared here.
     */
    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
    if (sscf == NULL || sscf->ssl.ctx == NULL) {
        return NGX_CONF_OK;
    }

    ctx = sscf->ssl.ctx;

    SSL_CTX_set_msg_callback(ctx, (void (*)(int, int, int, const void *,
                             size_t, SSL *, void *)) ngx_http_ja4_msg_callback);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ja4_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_connection_t        *c;
    ngx_http_ja4_ctx_t      *ctx;
    ngx_http_ja4_srv_conf_t *scf;
    u_char                  *out;
    size_t                   out_len;

    v->not_found = 1;

    c = r->connection;

    if (c == NULL || c->ssl == NULL || c->ssl->connection == NULL) {
        return NGX_OK;
    }

    scf = ngx_http_get_module_srv_conf(r, ngx_http_ja4_module);
    if (scf == NULL || !scf->enable) {
        return NGX_OK;
    }

    /*
     * $ssl_ja4_r and $ssl_ja4_o are debug variables: only exposed when
     * "ja4_debug_enable on".  $ssl_ja4 (data 0) and $ssl_ja4s (data 3)
     * are production variables and always available.
     */
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

/*
 * $http_ja4h - JA4H fingerprint of the HTTP request.
 *
 * Computed once per request and cached in the request context
 * (ngx_http_get_module_ctx).  Subsequent accesses reuse the cached
 * string: parse once, build once, hash once, then just return the buffer.
 */
static ngx_int_t
ngx_http_ja4h_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ja4_srv_conf_t *scf;
    ngx_http_ja4_ctx_t      *ctx;

    (void) data;

    v->not_found = 1;

    scf = ngx_http_get_module_srv_conf(r, ngx_http_ja4_module);
    if (scf == NULL || !scf->enable) {
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_ja4_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ja4_ctx_t));
        if (ctx == NULL) {
            return NGX_OK;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_ja4_module);
    }

    /* parse + build only once for the whole request lifetime */
    if (!ctx->done) {
        ngx_http_ja4_http_parse(r, ctx);
    }

    if (ctx->ja4h_len == 0) {
        return NGX_OK;
    }

    v->data = ctx->ja4h;
    v->len = ctx->ja4h_len;
    v->valid = 1;
    v->not_found = 0;
    v->no_cacheable = 1;

    return NGX_OK;
}

/*
 * OpenSSL message callback.  Fires for every TLS protocol message; we only
 * care about the received ClientHello handshake message.
 */
void
ngx_http_ja4_msg_callback(int write_p, int version, int content_type,
    const void *buf, size_t len, ngx_ssl_conn_t *ssl, void *arg)
{
    ngx_connection_t    *c;
    ngx_http_ja4_ctx_t  *ctx;
    ngx_flag_t           quic;

    (void) version;
    (void) arg;

    /*
     * OpenSSL invokes the message callback with content_type ==
     * SSL3_RT_HANDSHAKE for handshake messages; the handshake message type
     * lives in the first byte of buf.  JA4 (client) is computed from the
     * received ClientHello (write_p=0), JA4S (server) from the sent
     * ServerHello (write_p=1).
     */
    if (content_type != SSL3_RT_HANDSHAKE || buf == NULL) {
        return;
    }

    if (len < 4 || (((const u_char *) buf)[0] != SSL3_MT_CLIENT_HELLO
                    && ((const u_char *) buf)[0] != SSL3_MT_SERVER_HELLO))
    {
        return;
    }

    c = ngx_ssl_get_connection(ssl);
    if (c == NULL || c->ssl == NULL || c->pool == NULL || c->log == NULL) {
        return;
    }

    ctx = SSL_get_ex_data(ssl, ngx_http_ja4_ssl_index);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_http_ja4_ctx_t));
        if (ctx == NULL) {
            return;
        }
        SSL_set_ex_data(ssl, ngx_http_ja4_ssl_index, ctx);
    }

    /*
     * In this nginx, a QUIC (HTTP/3) connection has c->udp set once its
     * socket is created; a plain TLS/TCP connection always has c->udp NULL.
     */
    quic = (c->udp != NULL);

    /*
     * buf is the full handshake message including its 4-byte header:
     * [0] message type, [1..3] 24-bit length, then the message body.
     */
    if (((const u_char *) buf)[0] == SSL3_MT_CLIENT_HELLO) {
        ngx_http_ja4_parse(quic, (const u_char *) buf + 4, len - 4, ctx);

    } else if (!write_p) {
        /* received ServerHello: nothing to do for JA4/JA4S */

    } else {
        /* sent ServerHello: compute JA4S */
        ngx_http_ja4_tls_server_parse(quic, (const u_char *) buf + 4,
                                      len - 4, ctx);
    }
}

#endif /* NGX_HTTP_SSL */