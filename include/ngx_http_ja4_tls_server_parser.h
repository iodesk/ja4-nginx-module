/*
 * ngx_http_ja4_tls_server_parser.h
 *
 * Public API of the TLS ServerHello parser (JA4S).
 */

#ifndef _NGX_HTTP_JA4_TLS_SERVER_PARSER_H_INCLUDED_
#define _NGX_HTTP_JA4_TLS_SERVER_PARSER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_http_ja4.h>

/*
 * Parse a raw TLS ServerHello body (past the 4-byte handshake header)
 * and compute the JA4S fingerprint.
 *
 * quic: 1 when the connection is QUIC, 0 otherwise.
 * p/len: ServerHello body (version, random, session id, cipher,
 *        compression, extensions).
 * ctx: result context; ctx->ja4s is set on success.
 */
void ngx_http_ja4_tls_server_parse(ngx_flag_t quic, const u_char *p,
    size_t len, ngx_http_ja4_ctx_t *ctx);


#endif /* _NGX_HTTP_JA4_TLS_SERVER_PARSER_H_INCLUDED_ */