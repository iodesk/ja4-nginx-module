/*
 * ngx_http_ja4_tls_server_builder.h
 *
 * Public API of the TLS ServerHello fingerprint builder (JA4S).
 */

#ifndef _NGX_HTTP_JA4_TLS_SERVER_BUILDER_H_INCLUDED_
#define _NGX_HTTP_JA4_TLS_SERVER_BUILDER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_http_ja4.h>

/*
 * Build the JA4S string into ctx->ja4s.
 *
 *   A = ptype(1) version(2) ext_len(2) alpn(2)
 *   _B_ = the single server cipher (4 hex chars)
 *   _C_ = sha256(server extension list, comma separated, in order,
 *                GREASE included) first 12 hex
 */
void ngx_http_ja4_tls_server_build(ngx_http_ja4_ctx_t *ctx,
    ngx_flag_t quic, uint16_t version,
    const u_char *alpn, size_t alpn_len,
    size_t ext_count,
    uint16_t cipher,
    const u_char *ext_list, size_t ext_list_len);


#endif /* _NGX_HTTP_JA4_TLS_SERVER_BUILDER_H_INCLUDED_ */