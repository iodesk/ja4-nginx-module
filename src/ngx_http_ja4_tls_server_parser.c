/*
 * ngx_http_ja4_tls_server_parser.c
 *
 * Parses a raw TLS ServerHello body and computes the JA4S fingerprint
 * via the TLS server builder.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_ja4.h>
#include <ngx_http_ja4_tls_server_parser.h>
#include <ngx_http_ja4_tls_server_builder.h>


void
ngx_http_ja4_tls_server_parse(ngx_flag_t quic, const u_char *p, size_t len,
    ngx_http_ja4_ctx_t *ctx)
{
    static const u_char  hex[] = "0123456789abcdef";
    const u_char  *end, *cext_end;
    uint16_t       version_code;
    uint16_t       cipher;
    size_t         ext_count;
    u_char         alpn[2] = { '0', '0' };
    size_t         alpn_len = 0;

    u_char         ext_list[NGX_JA4_RAW_LEN];
    u_char        *ep;
    size_t         ext_list_len;

    uint16_t       ext_type, ext_len;
    size_t         slen, clen;

    ext_list_len = 0;

    if (len < 2) {
        return;
    }
    end = p + len;

    /* version */
    version_code = (uint16_t) (p[0] << 8 | p[1]);
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

    /* selected cipher suite (single) */
    if ((size_t) (end - p) < 2) {
        return;
    }
    cipher = (uint16_t) (p[0] << 8 | p[1]);
    p += 2;

    /* compression method */
    if ((size_t) (end - p) < 1) {
        return;
    }
    p += 1;

    /* extensions */
    ext_count = 0;
    ep = ext_list;

    if ((size_t) (end - p) < 2) {
        goto build;
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

        /* JA4S extension list includes GREASE and preserves order */
        if (ext_count < 99
            && (size_t) (ep + 5 - ext_list) <= NGX_JA4_RAW_LEN)
        {
            if (ext_count > 0) {
                *ep++ = ',';
            }
            *ep++ = hex[(ext_type >> 12) & 0xf];
            *ep++ = hex[(ext_type >> 8) & 0xf];
            *ep++ = hex[(ext_type >> 4) & 0xf];
            *ep++ = hex[ext_type & 0xf];
            ext_count++;
        }

        /* ALPN if present */
        if (ext_type == 0x0010 && ext_len >= 3) {
            size_t iv_len = p[2];
            if (iv_len >= 1 && iv_len + 3 <= ext_len) {
                alpn[0] = p[3];
                alpn[1] = p[3 + iv_len - 1];
                alpn_len = 2;
            }
        }

        /*
         * ServerHello supported_versions carries the negotiated TLS
         * version directly as a single ProtocolVersion (2 bytes), unlike
         * ClientHello which uses a length-prefixed list.  In TLS 1.3 the
         * legacy version field is 0x0303 but the real negotiated version
         * lives here (0x0304); use it when present, mirroring the
         * reference get_supported_version().
         */
        if (ext_type == 0x002b && ext_len >= 2) {
            uint16_t sv = (uint16_t) (p[0] << 8 | p[1]);
            if (!NGX_JA4_IS_GREASE(sv)) {
                version_code = sv;
            }
        }

        p += ext_len;
    }

build:
    ext_list_len = (size_t) (ep - ext_list);

    ngx_http_ja4_tls_server_build(ctx, quic, version_code,
                                  alpn, alpn_len,
                                  ext_count,
                                  cipher,
                                  ext_list, ext_list_len);
}