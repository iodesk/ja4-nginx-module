/*
 * ngx_http_ja4_tls_builder.c
 *
 * Builds the canonical JA4, JA4_r and JA4_o fingerprints from the
 * ClientHello fields extracted by the TLS parser.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_http_ja4.h>
#include <ngx_http_ja4_tls_builder.h>
#include <ngx_http_ja4_crypto.h>

#include <ctype.h>
#include <stdio.h>


/*
 * Build the "_a_" section shared by all three JA4 variants.
 * Returns the end pointer.
 */
static u_char *
ngx_http_ja4_build_a(u_char *bp, ngx_uint_t protocol, uint16_t version,
    ngx_flag_t has_sni, const u_char *alpn, size_t alpn_len,
    size_t total_ciphers, size_t total_exts)
{
    static const u_char  hex[] = "0123456789abcdef";
    size_t      n;
    u_char      a, b;

    /* protocol: t (TLS over TCP), q (QUIC), d (DTLS) */
    if (protocol == 1) {
        *bp++ = 'q';
    } else if (protocol == 2) {
        *bp++ = 'd';
    } else {
        *bp++ = 't';
    }

    /* TLS version */
    switch (version) {
    case 0x0304: *bp++ = '1'; *bp++ = '3'; break;
    case 0x0303: *bp++ = '1'; *bp++ = '2'; break;
    case 0x0302: *bp++ = '1'; *bp++ = '1'; break;
    case 0x0301: *bp++ = '1'; *bp++ = '0'; break;
    case 0x0300: *bp++ = 's'; *bp++ = '3'; break;
    default:     *bp++ = '0'; *bp++ = '0'; break;
    }

    /* SNI */
    *bp++ = has_sni ? 'd' : 'i';

    /* cipher count (max 99) */
    n = ngx_min(total_ciphers, 99);
    *bp++ = (u_char) ('0' + n / 10);
    *bp++ = (u_char) ('0' + n % 10);

    /* extension count (max 99) */
    n = ngx_min(total_exts, 99);
    *bp++ = (u_char) ('0' + n / 10);
    *bp++ = (u_char) ('0' + n % 10);

    /* ALPN first/last of first value */
    if (alpn_len == 2) {
        a = alpn[0];
        b = alpn[1];
        if (isalnum(a) && isalnum(b)) {
            *bp++ = a;
            *bp++ = b;
        } else {
            *bp++ = hex[(a >> 4) & 0xf];
            *bp++ = hex[b & 0xf];
        }
    } else {
        *bp++ = '0';
        *bp++ = '0';
    }

    /* separator */
    *bp++ = '_';

    return bp;
}


/*
 * Write the comma-separated, lower-case 4-digit hex list of values.
 * Returns bytes written.
 */
static size_t
ngx_http_ja4_hexlist(u_char *p, uint16_t *a, size_t n)
{
    static const u_char  hex[] = "0123456789abcdef";
    u_char               *start = p;
    size_t               i;

    for (i = 0; i < n; i++) {
        if (i != 0) {
            *p++ = ',';
        }
        *p++ = hex[(a[i] >> 12) & 0xf];
        *p++ = hex[(a[i] >> 8) & 0xf];
        *p++ = hex[(a[i] >> 4) & 0xf];
        *p++ = hex[a[i] & 0xf];
    }
    return (size_t) (p - start);
}


/*
 * Insertion sort of uint16_t, ascending.
 */
static void
ngx_http_ja4_sort2(uint16_t *a, size_t n)
{
    size_t    i, j;
    uint16_t  t;

    for (i = 1; i < n; i++) {
        t = a[i];
        for (j = i; j > 0 && a[j - 1] > t; j--) {
            a[j] = a[j - 1];
        }
        a[j] = t;
    }
}


/*
 * Compute all three JA4 strings:
 *   canonical  t13d1516h2_8daaf6152771_e5627efa2ab1
 *          r   t13d1516h2_<sorted-ciphers>_<sorted-exts>_<sigalgs>
 *          o   t13d1516h2_<ciphers>_<exts incl SNI/ALPN>_<sigalgs>
 */
void
ngx_http_ja4_build(ngx_http_ja4_ctx_t *ctx, uint16_t version,
    ngx_flag_t quic, ngx_flag_t has_sni, const u_char *alpn, size_t alpn_len,
    uint16_t *ciphers, size_t nciph, size_t total_ciphers,
    uint16_t *exts, size_t next, size_t total_exts,
    uint16_t *exts_o, size_t next_o,
    uint16_t *sigalgs, size_t nsigalg)
{
    u_char        buf[8192], digest[32], *bp, *p;
    size_t        n;
    ngx_uint_t    protocol = quic ? 1 : 0;

    /* JA4_o uses ORIGINAL order: build it before sorting arrays in place */
    p = ctx->ja4_o;
    p = ngx_http_ja4_build_a(p, protocol, version, has_sni, alpn, alpn_len,
                             total_ciphers, total_exts);

    if (nciph != 0) {
        p += ngx_http_ja4_hexlist(p, ciphers, nciph);
    }
    *p++ = '_';

    if (next_o != 0) {
        p += ngx_http_ja4_hexlist(p, exts_o, next_o);
    }
    if (nsigalg != 0) {
        *p++ = '_';
        p += ngx_http_ja4_hexlist(p, sigalgs, nsigalg);
    }

    ctx->ja4_o_len = (size_t) (p - ctx->ja4_o);

    /* sort once; canonical and _r reuse sorted arrays */
    ngx_http_ja4_sort2(ciphers, nciph);
    ngx_http_ja4_sort2(exts, next);

    /* ---- canonical JA4 ---- */
    bp = ctx->ja4;
    bp = ngx_http_ja4_build_a(bp, protocol, version, has_sni, alpn, alpn_len,
                              total_ciphers, total_exts);

    n = ngx_http_ja4_hexlist(buf, ciphers, nciph);
    if (nciph != 0) {
        ngx_http_ja4_sha256(buf, n, digest);
        bp = ngx_hex_dump(bp, digest, 6);
    } else {
        ngx_memcpy(bp, "000000000000", 12);
        bp += 12;
    }

    *bp++ = '_';

    if (next != 0 || nsigalg != 0) {
        n = ngx_http_ja4_hexlist(buf, exts, next);
        if (nsigalg != 0) {
            buf[n++] = '_';
            n += ngx_http_ja4_hexlist(buf + n, sigalgs, nsigalg);
        }
        ngx_http_ja4_sha256(buf, n, digest);
        bp = ngx_hex_dump(bp, digest, 6);
    } else {
        ngx_memcpy(bp, "000000000000", 12);
        bp += 12;
    }

    ctx->ja4_len = (size_t) (bp - ctx->ja4);

    /* ---- JA4_r (raw, sorted) ---- */
    p = ctx->ja4_r;
    p = ngx_http_ja4_build_a(p, protocol, version, has_sni, alpn, alpn_len,
                             total_ciphers, total_exts);

    if (nciph != 0) {
        p += ngx_http_ja4_hexlist(p, ciphers, nciph);
    }
    *p++ = '_';

    if (next != 0) {
        p += ngx_http_ja4_hexlist(p, exts, next);
    }
    if (nsigalg != 0) {
        *p++ = '_';
        p += ngx_http_ja4_hexlist(p, sigalgs, nsigalg);
    }

    ctx->ja4_r_len = (size_t) (p - ctx->ja4_r);

    ctx->done = 1;
}