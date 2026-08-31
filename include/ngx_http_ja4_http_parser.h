/*
 * ngx_http_ja4_http_parser.h
 *
 * Public API of the HTTP request parser (JA4H).
 */

#ifndef _NGX_HTTP_JA4_HTTP_PARSER_H_INCLUDED_
#define _NGX_HTTP_JA4_HTTP_PARSER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_ja4.h>

/*
 * Compute the JA4H fingerprint of an HTTP request.
 *
 * Data is read directly from the nginx request structure
 * (r->headers_in / r->method / r->http_version); the result is stored in
 * ctx->ja4h and ctx->done is set on success.
 */
void ngx_http_ja4_http_parse(ngx_http_request_t *r, ngx_http_ja4_ctx_t *ctx);


#endif /* _NGX_HTTP_JA4_HTTP_PARSER_H_INCLUDED_ */