/*
 * ngx_http_ja4_http_builder.c
 *
 * Builds the JA4H fingerprint from the HTTP request fields extracted by
 * the HTTP parser.
 *
 * JA4H layout (FoxIO reference implementation):
 *   A_B_C_D
 *   A = method(2) version(2) cookie(1) referer(1) header_count(2) lang(4)
 *   B = sha256(header names in request order, comma separated), 12 hex
 *   C = sha256(cookie names sorted, comma separated), 12 hex
 *   D = sha256(cookie values sorted, comma separated), 12 hex
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_ja4.h>
#include <ngx_http_ja4_http_builder.h>
#include <ngx_http_ja4_crypto.h>

#include <ctype.h>


/*
 * Normalize Accept-Language to the JA4H form:
 * lowercase, strip '-', stop at first ',' or ';', pad to 4 chars.
 */
static void
ngx_http_ja4_http_lang(u_char out[4], const u_char *lang, size_t len)
{
    size_t  i, n;
    u_char  c;

    n = 0;
    for (i = 0; i < len && n < 4; i++) {
        c = lang[i];

        if (c == ',' || c == ';') {
            break;
        }

        if (c == '-') {
            continue;
        }

        out[n++] = (u_char) tolower(c);
    }

    while (n < 4) {
        out[n++] = '0';
    }
}


void
ngx_http_ja4_http_build(ngx_http_ja4_ctx_t *ctx,
    const u_char *method, size_t method_len,
    ngx_uint_t http_version,
    ngx_flag_t has_cookie, ngx_flag_t has_referer,
    size_t header_count,
    const u_char *lang, size_t lang_len,
    const u_char *raw_headers, size_t raw_headers_len,
    const u_char *cookie_names, size_t cookie_names_len,
    const u_char *cookie_values, size_t cookie_values_len)
{
    u_char  *p, digest[32];
    u_char   langbuf[4];
    size_t   n;

    p = ctx->ja4h;

    /* method: lowercase, first 2 chars */
    *p++ = (u_char) tolower(method_len > 0 ? method[0] : '0');
    *p++ = (u_char) tolower(method_len > 1 ? method[1] : '0');

    /* version: "10", "11" or "20" */
    if (http_version == NGX_HTTP_VERSION_20) {
        *p++ = '2';
        *p++ = '0';
    } else if (http_version == NGX_HTTP_VERSION_10) {
        *p++ = '1';
        *p++ = '0';
    } else {
        *p++ = '1';
        *p++ = '1';
    }

    /* cookie / referer presence */
    *p++ = has_cookie ? 'c' : 'n';
    *p++ = has_referer ? 'r' : 'n';

    /* header count (min 99) */
    n = ngx_min(header_count, 99);
    *p++ = (u_char) ('0' + n / 10);
    *p++ = (u_char) ('0' + n % 10);

    /* language */
    ngx_http_ja4_http_lang(langbuf, lang, lang_len);
    *p++ = langbuf[0];
    *p++ = langbuf[1];
    *p++ = langbuf[2];
    *p++ = langbuf[3];

    /* B: header order */
    *p++ = '_';
    if (raw_headers_len != 0) {
        ngx_http_ja4_sha256(raw_headers, raw_headers_len, digest);
        p = ngx_hex_dump(p, digest, 6);
    } else {
        ngx_memcpy(p, "000000000000", 12);
        p += 12;
    }

    /* C: cookie names */
    *p++ = '_';
    if (cookie_names_len != 0) {
        ngx_http_ja4_sha256(cookie_names, cookie_names_len, digest);
        p = ngx_hex_dump(p, digest, 6);
    } else {
        ngx_memcpy(p, "000000000000", 12);
        p += 12;
    }

    /* D: cookie values */
    *p++ = '_';
    if (cookie_values_len != 0) {
        ngx_http_ja4_sha256(cookie_values, cookie_values_len, digest);
        p = ngx_hex_dump(p, digest, 6);
    } else {
        ngx_memcpy(p, "000000000000", 12);
        p += 12;
    }

    ctx->ja4h_len = (size_t) (p - ctx->ja4h);
    ctx->done = 1;
}