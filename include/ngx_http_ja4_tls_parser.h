/*
 * ngx_http_ja4_tls_parser.h
 *
 * Public API of the TLS ClientHello parser.
 */

#ifndef _NGX_HTTP_JA4_TLS_PARSER_H_INCLUDED_
#define _NGX_HTTP_JA4_TLS_PARSER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_http_ja4.h>

/*
 * Parse a raw TLS ClientHello body (past the 4-byte handshake header),
 * extract the fields JA4 needs and build the fingerprints.
 *
 * quic: 1 when the connection is QUIC (HTTP/3), 0 otherwise.
 * p/len: ClientHello body (legacy_version, random, session id, cipher
 *        suites, compression, extensions).
 * ctx: per-connection result context; on success ctx->done is set.
 */
void ngx_http_ja4_parse(ngx_flag_t quic, const u_char *p, size_t len,
    ngx_http_ja4_ctx_t *ctx);


#endif /* _NGX_HTTP_JA4_TLS_PARSER_H_INCLUDED_ */