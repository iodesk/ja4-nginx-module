/*
 * ngx_http_ja4_tls_server_builder.c
 *
 * Builds the JA4S fingerprint from the ServerHello fields extracted by
 * the TLS server parser.
 *
 * JA4S layout (FoxIO reference implementation):
 *   A_B_C
 *   A = ptype(1) version(2) ext_len(2) alpn(2)
 *   B = single server cipher (4 hex chars)
 *   C = sha256(server extensions in order, GREASE included) first 12 hex
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_ja4.h>
#include <ngx_http_ja4_tls_server_builder.h>
#include <ngx_http_ja4_crypto.h>

#include <ctype.h>


void
ngx_http_ja4_tls_server_build(ngx_http_ja4_ctx_t *ctx,
    ngx_flag_t quic, uint16_t version,
    const u_char *alpn, size_t alpn_len,
    size_t ext_count,
    uint16_t cipher,
    const u_char *ext_list, size_t ext_list_len)
{
    static const u_char  hex[] = "0123456789abcdef";
    u_char  *p, digest[32];
    size_t   n;

    p = ctx->ja4s;

    /* ptype: t (TLS over TCP), q (QUIC) */
    *p++ = quic ? 'q' : 't';

    /* version */
    switch (version) {
    case 0x0304: *p++ = '1'; *p++ = '3'; break;
    case 0x0303: *p++ = '1'; *p++ = '2'; break;
    case 0x0302: *p++ = '1'; *p++ = '1'; break;
    case 0x0301: *p++ = '1'; *p++ = '0'; break;
    case 0x0300: *p++ = 's'; *p++ = '3'; break;
    default:     *p++ = '0'; *p++ = '0'; break;
    }

    /* extension count (min 99) */
    n = ngx_min(ext_count, 99);
    *p++ = (u_char) ('0' + n / 10);
    *p++ = (u_char) ('0' + n % 10);

    /* ALPN first/last of first value */
    if (alpn_len == 2) {
        u_char a = alpn[0], b = alpn[1];
        if (isalnum(a) && isalnum(b)) {
            *p++ = a;
            *p++ = b;
        } else {
            *p++ = hex[(a >> 4) & 0xf];
            *p++ = hex[b & 0xf];
        }
    } else {
        *p++ = '0';
        *p++ = '0';
    }

    /* B: single server cipher */
    *p++ = '_';
    *p++ = hex[(cipher >> 12) & 0xf];
    *p++ = hex[(cipher >> 8) & 0xf];
    *p++ = hex[(cipher >> 4) & 0xf];
    *p++ = hex[cipher & 0xf];

    /* C: hash of server extensions in order */
    *p++ = '_';
    if (ext_list_len != 0) {
        ngx_http_ja4_sha256(ext_list, ext_list_len, digest);
        p = ngx_hex_dump(p, digest, 6);
    } else {
        ngx_memcpy(p, "000000000000", 12);
        p += 12;
    }

    ctx->ja4s_len = (size_t) (p - ctx->ja4s);
}