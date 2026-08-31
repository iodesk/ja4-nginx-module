/*
 * ngx_http_ja4_tls_builder.h
 *
 * Public API of the TLS fingerprint builder.
 */

#ifndef _NGX_HTTP_JA4_TLS_BUILDER_H_INCLUDED_
#define _NGX_HTTP_JA4_TLS_BUILDER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_http_ja4.h>

/*
 * Build the canonical JA4, JA4_r and JA4_o fingerprints from the ClientHello
 * fields already extracted by the parser.
 *
 * ciphers: cipher suites in the client's original order, GREASE excluded.
 * exts:    extensions excluding SNI (0000) and ALPN (0010).
 * exts_o:  all extensions (including SNI and ALPN) in original order.
 * sigalgs: signature algorithms in original order.
 * total_*: raw counts (used by the "_a_" section, capped at 99).
 *
 * On success writes the three strings into ctx and sets ctx->done.
 */
void ngx_http_ja4_build(ngx_http_ja4_ctx_t *ctx, uint16_t version,
    ngx_flag_t quic, ngx_flag_t has_sni, const u_char *alpn, size_t alpn_len,
    uint16_t *ciphers, size_t nciph, size_t total_ciphers,
    uint16_t *exts, size_t next, size_t total_exts,
    uint16_t *exts_o, size_t next_o,
    uint16_t *sigalgs, size_t nsigalg);


#endif /* _NGX_HTTP_JA4_TLS_BUILDER_H_INCLUDED_ */