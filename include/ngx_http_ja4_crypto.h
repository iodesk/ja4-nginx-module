/*
 * ngx_http_ja4_crypto.h
 *
 * Public API of the crypto utilities.
 */

#ifndef _NGX_HTTP_JA4_CRYPTO_H_INCLUDED_
#define _NGX_HTTP_JA4_CRYPTO_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * Compute the SHA-256 digest of data[0..len) into digest (32 bytes).
 */
void ngx_http_ja4_sha256(const u_char *data, size_t len, u_char digest[32]);


#endif /* _NGX_HTTP_JA4_CRYPTO_H_INCLUDED_ */