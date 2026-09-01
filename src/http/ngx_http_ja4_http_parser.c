/*
 * ngx_http_ja4_http_parser.c
 *
 * Extracts the HTTP request fields JA4H needs directly from the nginx
 * request structure and computes the JA4H fingerprint via the builder.
 *
 * Runs at most once per request (cached in the request context by the
 * module).  All temporary buffers are fixed-size stack arrays; no
 * pool allocation happens in the JA4H hot path.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

#include <ngx_http_ja4.h>
#include <ngx_http_ja4_http_parser.h>
#include <ngx_http_ja4_http_builder.h>

#include <string.h>


#define NGX_JA4H_HEADERS_BUF   512
#define NGX_JA4H_COOKIE_BUF    2048
#define NGX_JA4H_MAX_COOKIES   99


typedef struct {
    u_char *name;
    u_char *value;
    size_t  name_len;
    size_t  value_len;
} ngx_http_ja4_cookie_t;


static int
ngx_http_ja4_cookie_cmp(const ngx_http_ja4_cookie_t *a,
    const ngx_http_ja4_cookie_t *b)
{
    size_t  n;
    int     rc;

    n = ngx_min(a->name_len, b->name_len);
    rc = (n == 0) ? 0 : ngx_strncasecmp(a->name, b->name, n);

    if (rc == 0) {
        rc = (a->name_len < b->name_len) ? -1
           : (a->name_len > b->name_len) ? 1 : 0;
    }

    return rc;
}


/*
 * Split the Cookie header into name/value pairs, sort by name, and write
 * two comma separated strings (names and values) into the caller's fixed
 * buffers.
 */
static ngx_uint_t
ngx_http_ja4_parse_cookies(const u_char *data, size_t len,
    u_char *names, size_t names_cap,
    u_char *values, size_t values_cap,
    size_t *names_len, size_t *values_len)
{
    ngx_http_ja4_cookie_t  cookies[NGX_JA4H_MAX_COOKIES];
    const u_char           *cp, *end, *cend, *eq;
    u_char                 *np, *vp;
    size_t                  ncookies;
    ngx_uint_t              i, j, written;

    *names_len = 0;
    *values_len = 0;

    if (len == 0) {
        return 0;
    }

    ncookies = 0;
    cp = data;
    end = data + len;

    for (;;) {
        cend = memchr(cp, ';', end - cp);
        if (cend == NULL) {
            cend = end;
        }

        while (cp < cend && *cp == ' ') {
            cp++;
        }

        if (cp < cend) {
            eq = memchr(cp, '=', cend - cp);

            if (eq == NULL) {
                cookies[ncookies].name = (u_char *) cp;
                cookies[ncookies].name_len = cend - cp;
                cookies[ncookies].value = (u_char *) cend;
                cookies[ncookies].value_len = 0;
            } else {
                cookies[ncookies].name = (u_char *) cp;
                cookies[ncookies].name_len = eq - cp;
                cookies[ncookies].value = (u_char *) eq + 1;
                cookies[ncookies].value_len = cend - (eq + 1);
            }
            ncookies++;

            if (ncookies >= NGX_JA4H_MAX_COOKIES) {
                break;
            }
        }

        if (cend == end) {
            break;
        }
        cp = cend + 1;
    }

    if (ncookies == 0) {
        return 0;
    }

    /* insertion sort by name */
    for (i = 1; i < ncookies; i++) {
        ngx_http_ja4_cookie_t  tc = cookies[i];
        for (j = i; j > 0
             && ngx_http_ja4_cookie_cmp(&cookies[j - 1], &tc) > 0; j--)
        {
            cookies[j] = cookies[j - 1];
        }
        cookies[j] = tc;
    }

    np = names;
    vp = values;
    written = 0;

    for (i = 0; i < ncookies; i++) {
        if ((size_t) (np - names) + cookies[i].name_len + 1 > names_cap
            || (size_t) (vp - values) + cookies[i].value_len + 1 > values_cap)
        {
            break;
        }

        if (i > 0) {
            *np++ = ',';
            *vp++ = ',';
        }
        ngx_memcpy(np, cookies[i].name, cookies[i].name_len);
        np += cookies[i].name_len;
        ngx_memcpy(vp, cookies[i].value, cookies[i].value_len);
        vp += cookies[i].value_len;
        written++;
    }

    *names_len = (size_t) (np - names);
    *values_len = (size_t) (vp - values);

    return written;
}


void
ngx_http_ja4_http_parse(ngx_http_request_t *r, ngx_http_ja4_ctx_t *ctx)
{
    ngx_list_part_t    *part;
    ngx_table_elt_t    *h;
    ngx_uint_t          i, k;
    ngx_flag_t          has_cookie, has_referer;
    size_t              header_count;
    u_char              buf[NGX_JA4H_HEADERS_BUF], *bp, *last;
    u_char              names[NGX_JA4H_COOKIE_BUF];
    u_char              values[NGX_JA4H_COOKIE_BUF];
    size_t              names_len, values_len;
    u_char              *lang = NULL;
    size_t              lang_len = 0;

    has_cookie = (r->headers_in.cookie != NULL) ? 1 : 0;
    has_referer = (r->headers_in.referer != NULL) ? 1 : 0;

    bp = buf;
    last = buf + sizeof(buf);
    header_count = 0;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == 0 || h[i].key.data[0] == ':') {
            continue;
        }
        if (h[i].key.len == 6
            && ngx_strncasecmp(h[i].key.data,
                               (u_char *) "cookie", 6) == 0)
        {
            continue;
        }
        if (h[i].key.len == 7
            && ngx_strncasecmp(h[i].key.data,
                               (u_char *) "referer", 7) == 0)
        {
            continue;
        }

        /*
         * Accept-Language is kept in the header list (counts toward header
         * count and section B) but its value is also captured for the
         * language field, independent of the NGX_HTTP_HEADERS compile flag.
         */
        if (lang == NULL
            && h[i].key.len == 15
            && ngx_strncasecmp(h[i].key.data,
                               (u_char *) "accept-language", 15) == 0)
        {
            lang = h[i].value.data;
            lang_len = h[i].value.len;
        }

        if (header_count > 0) {
            if ((size_t) (last - bp) < 1) {
                break;
            }
            *bp++ = ',';
        }
        if ((size_t) (last - bp) < h[i].key.len) {
            break;
        }
        for (k = 0; k < h[i].key.len; k++) {
            *bp++ = ngx_tolower(h[i].key.data[k]);
        }
        header_count++;
    }

    names_len = 0;
    values_len = 0;

    if (has_cookie) {
        ngx_http_ja4_parse_cookies(
            r->headers_in.cookie->value.data,
            r->headers_in.cookie->value.len,
            names, sizeof(names), values, sizeof(values),
            &names_len, &values_len);
    }

    ngx_http_ja4_http_build(ctx,
                            r->method_name.data, r->method_name.len,
                            r->http_version,
                            has_cookie, has_referer,
                            header_count,
                            lang, lang_len,
                            buf, (size_t) (bp - buf),
                            names, names_len,
                            values, values_len);
}