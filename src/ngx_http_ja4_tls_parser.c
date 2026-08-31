/*
 * ngx_http_ja4_tls_parser.c
 *
 * Parses a raw TLS ClientHello body and hands the extracted fields to the
 * TLS fingerprint builder.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_http_ja4.h>
#include <ngx_http_ja4_tls_parser.h>
#include <ngx_http_ja4_tls_builder.h>


/*
 * Parse a raw TLS ClientHello body (past the 4-byte handshake header)
 * and compute the JA4 fingerprint.
 */
void
ngx_http_ja4_parse(ngx_flag_t quic, const u_char *p, size_t len,
    ngx_http_ja4_ctx_t *ctx)
{
    const u_char  *end, *cext_end;
    uint16_t       version_code;
    u_char         alpn[2] = { '0', '0' };
    size_t         alpn_len = 0;
    ngx_flag_t     has_sni = 0;
    ngx_flag_t     has_supported_versions = 0;
    uint16_t       supported_version = 0;
    uint16_t       legacy_version = 0;

    uint16_t       ciphers[NGX_JA4_MAX_FIELDS];
    uint16_t       exts[NGX_JA4_MAX_FIELDS];    /* excl. SNI/ALPN (for hash) */
    uint16_t       exts_o[NGX_JA4_MAX_FIELDS];  /* incl. SNI/ALPN, original */
    uint16_t       sigalgs[NGX_JA4_MAX_FIELDS];
    size_t         nciph = 0, next = 0, next_o = 0, nsigalg = 0;
    size_t         total_ciphers = 0, total_exts = 0;

    uint16_t       n, ext_type, ext_len;
    size_t         slen, ciphers_len, clen, i;

    if (len < 2) {
        return;
    }
    end = p + len;

    /* legacy_version */
    legacy_version = (uint16_t) (p[0] << 8 | p[1]);
    p += 2;

    /* random (32 bytes) */
    if ((size_t) (end - p) < 32) {
        return;
    }
    p += 32;

    /* session id */
    if ((size_t) (end - p) < 1) {
        return;
    }
    slen = *p++;
    if ((size_t) (end - p) < slen) {
        return;
    }
    p += slen;

    /* cipher suites */
    if ((size_t) (end - p) < 2) {
        return;
    }
    ciphers_len = (uint16_t) (p[0] << 8 | p[1]);
    p += 2;
    if ((ciphers_len & 1) || (size_t) (end - p) < ciphers_len) {
        return;
    }
    for (i = 0; i < ciphers_len; i += 2) {
        n = (uint16_t) (p[i] << 8 | p[i + 1]);
        if (!NGX_JA4_IS_GREASE(n)) {
            total_ciphers++;
            if (nciph < NGX_JA4_MAX_FIELDS) {
                ciphers[nciph++] = n;
            }
        }
    }
    p += ciphers_len;

    /* compression methods */
    if ((size_t) (end - p) < 1) {
        return;
    }
    clen = *p++;
    if ((size_t) (end - p) < clen) {
        return;
    }
    p += clen;

    /* extensions */
    if ((size_t) (end - p) < 2) {
        return;
    }
    clen = (uint16_t) (p[0] << 8 | p[1]);
    p += 2;
    if ((size_t) (end - p) < clen) {
        return;
    }
    cext_end = p + clen;

    while ((size_t) (cext_end - p) >= 4) {
        ext_type = (uint16_t) (p[0] << 8 | p[1]);
        ext_len  = (uint16_t) (p[2] << 8 | p[3]);
        p += 4;

        if ((size_t) (cext_end - p) < ext_len) {
            return;
        }

        if (NGX_JA4_IS_GREASE(ext_type)) {
            p += ext_len;
            continue;
        }

        total_exts++;

        /* original order, includes SNI+ALPN (for JA4_o) */
        if (next_o < NGX_JA4_MAX_FIELDS) {
            exts_o[next_o++] = ext_type;
        }

        switch (ext_type) {

        case 0x0000: /* server_name; excluded from _c_ */
            has_sni = 1;
            break;

        case 0x0010: /* ALPN parsed here; excluded from _c_ */
            if (ext_len >= 3) {
                size_t iv_len = p[2];
                if (iv_len >= 1 && iv_len + 3 <= ext_len) {
                    alpn[0] = p[3];
                    alpn[1] = p[3 + iv_len - 1];
                    alpn_len = 2;
                }
            }
            break;

        case 0x000d: /* signature_algorithms */
            if (next < NGX_JA4_MAX_FIELDS) {
                exts[next++] = ext_type;
            }
            if (ext_len >= 2) {
                size_t seg = (uint16_t) (p[0] << 8 | p[1]);
                if (seg + 2 <= ext_len && (seg & 1) == 0) {
                    for (i = 2; i + 1 < ext_len; i += 2) {
                        n = (uint16_t) (p[i] << 8 | p[i + 1]);
                        if (!NGX_JA4_IS_GREASE(n)
                            && nsigalg < NGX_JA4_MAX_FIELDS)
                        {
                            sigalgs[nsigalg++] = n;
                        }
                    }
                }
            }
            break;

        case 0x002b: /* supported_versions */
            if (next < NGX_JA4_MAX_FIELDS) {
                exts[next++] = ext_type;
            }
            if (ext_len >= 1) {
                has_supported_versions = 1;
                /*
                 * Body of the supported_versions extension is:
                 *   [1 byte vector length][2*n byte ProtocolVersion list]
                 * The first version entry starts at offset 1, so the loop
                 * must start at i = 1 (offset 0 holds the vector length).
                 */
                for (i = 1; i + 1 < ext_len; i += 2) {
                    n = (uint16_t) (p[i] << 8 | p[i + 1]);
                    if (!NGX_JA4_IS_GREASE(n) && n > supported_version) {
                        supported_version = n;
                    }
                }
            }
            break;

        default:
            if (next < NGX_JA4_MAX_FIELDS) {
                exts[next++] = ext_type;
            }
            break;
        }

        p += ext_len;
    }

    if (has_supported_versions && supported_version != 0) {
        version_code = supported_version;
    } else {
        version_code = legacy_version;
    }

    ngx_http_ja4_build(ctx, version_code, quic, has_sni,
                       alpn, alpn_len,
                       ciphers, nciph, total_ciphers,
                       exts, next, total_exts,
                       exts_o, next_o,
                       sigalgs, nsigalg);
}