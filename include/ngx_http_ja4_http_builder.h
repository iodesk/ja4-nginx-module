/*
 * ngx_http_ja4_http_builder.h
 *
 * Public API of the HTTP fingerprint builder (JA4H).
 */

#ifndef _NGX_HTTP_JA4_HTTP_BUILDER_H_INCLUDED_
#define _NGX_HTTP_JA4_HTTP_BUILDER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_http_ja4.h>

/*
 * Build the JA4H string into ctx->ja4h.
 *
 *   A = method(2) + version(2) + cookie(1) + referer(1)
 *       + header_count(2) + language(4)
 *   B = sha256(header names in order, comma separated) first 12 hex
 *   C = sha256(cookie names sorted, comma separated) first 12 hex
 *   D = sha256(cookie values sorted, comma separated) first 12 hex
 *
 * raw_headers: original header names (cookie and referer excluded,
 *              pseudo headers excluded), in request order.
 * cookie_names / cookie_values: sorted by cookie name.
 * lang: normalized Accept-Language.
 * On success writes ctx->ja4h and sets ctx->done.
 */
void ngx_http_ja4_http_build(ngx_http_ja4_ctx_t *ctx,
    const u_char *method, size_t method_len,
    ngx_uint_t http_version,
    ngx_flag_t has_cookie, ngx_flag_t has_referer,
    size_t header_count,
    const u_char *lang, size_t lang_len,
    const u_char *raw_headers, size_t raw_headers_len,
    const u_char *cookie_names, size_t cookie_names_len,
    const u_char *cookie_values, size_t cookie_values_len);


#endif /* _NGX_HTTP_JA4_HTTP_BUILDER_H_INCLUDED_ */