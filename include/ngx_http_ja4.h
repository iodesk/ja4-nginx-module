/*
 * ngx_http_ja4.h
 *
 * Shared types, constants and macros for the JA4 module.
 *
 * This header is the single place for structures and definitions shared
 * across the module / parser / builder / crypto layers.  Component-specific
 * API lives in the layer headers (ngx_http_ja4_parser.h,
 * ngx_http_ja4_builder.h, ngx_http_ja4_crypto.h).
 */

#ifndef _NGX_HTTP_JA4_H_INCLUDED_
#define _NGX_HTTP_JA4_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>

/*
 * GREASE values (RFC 8701): both bytes equal and each byte has 0x?A pattern,
 * i.e. 0x0a0a, 0x1a1a, ..., 0xfafa.  JA4 ignores GREASE everywhere.
 */
#define NGX_JA4_IS_GREASE(v)                                                    \
    ((((v) & 0x0f0f) == 0x0a0a) && (((v) & 0xff) == ((v) >> 8)))

#define NGX_JA4_MAX_FIELDS   256
#define NGX_JA4_RAW_LEN      1024


typedef struct {
    ngx_flag_t  enable;
    ngx_flag_t  debug_enable;
} ngx_http_ja4_srv_conf_t;


/*
 * Per-connection result context.
 *
 * Allocated from the connection pool by the module and passed down to the
 * parser and builder.  It owns the three output buffers produced by the
 * builder and read back by the variable handler.
 */
typedef struct {
    u_char     ja4[36];              /* canonical JA4 fingerprint         */
    size_t     ja4_len;
    u_char     ja4_r[NGX_JA4_RAW_LEN]; /* raw, sorted                     */
    size_t     ja4_r_len;
    u_char     ja4_o[NGX_JA4_RAW_LEN]; /* raw, original order             */
    size_t     ja4_o_len;
    u_char     ja4h[64];             /* JA4H fingerprint                  */
    size_t     ja4h_len;
    u_char     ja4s[32];             /* JA4S fingerprint                  */
    size_t     ja4s_len;
    unsigned   done:1;
} ngx_http_ja4_ctx_t;


#endif /* _NGX_HTTP_JA4_H_INCLUDED_ */