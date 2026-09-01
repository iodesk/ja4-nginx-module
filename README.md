# ja4-nginx-module

JA4+ TLS fingerprint as a standalone nginx module.

Zero changes to nginx core. Zero changes to OpenSSL. Just drop it in and build.

The module hooks into OpenSSL's message callback (`SSL_CTX_set_msg_callback`) on each server's existing `SSL_CTX`, parses the raw TLS ClientHello/ServerHello, and computes JA4/JA4S/JA4H fingerprints per the [FoxIO JA4+ specification](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md).

## Fingerprints

| Fingerprint | Variable | Scope | Source | Example |
|---|---|---|---|---|
| JA4 | `$ssl_ja4` | connection | TLS ClientHello | `t13d1516h2_8daaf6152771_e5627efa2ab1` |
| JA4S | `$ssl_ja4s` | connection | TLS ServerHello | `t130200_1302_a56c5b993250` |
| JA4H | `$http_ja4h` | request | HTTP headers | `ge11cr06enus_8c2f9ef95269_d23bf79698dc_69e42fa741fe` |
| JA4_r | `$ssl_ja4_r` | connection | Raw JA4 (debug) | `t13d1516h2_002f,..._0403,...` |
| JA4_o | `$ssl_ja4_o` | connection | Raw JA4 original order (debug) | `t13d1516h2_1301,..._0403,...` |

Available in both `http {}` and `stream {}` contexts (JA4/JA4S only for stream).

## Architecture

```text
                    ┌──────────────────────────────────────┐
                    │           ngx_http_ja4_module        │
                    │  (HTTP: JA4 + JA4S + JA4H)           │
                    ├──────────────────────────────────────┤
                    │  SSL_CTX_set_msg_callback            │
                    │         │             │              │
                    │    tls_parser    tls_server_parser   │
                    │      (JA4)         (JA4S)            │
                    │         │             │              │
                    │    tls_builder   tls_server_builder  │
                    │         │             │              │
                    │    http_parser / http_builder        │
                    │         (JA4H)                       │
                    │              │                       │
                    │           crypto                     │
                    │       (SHA-256)                      │
                    ├──────────────────────────────────────┤
                    │         ngx_stream_ja4_module        │
                    │  (Stream: JA4 + JA4S)                │
                    │  Reuses shared SSL ex-data index     │
                    │  and callback function from HTTP      │
                    └──────────────────────────────────────┘
```

## Benchmark

Measured overhead of the module against plain nginx on the same server.

| Scenario | Baseline | JA4 on | Overhead |
|---|---|---|---|
| Keep-alive (100 conns, 60s) | 1957 req/s | 1957 req/s | **0.00%** |
| Connection: close (100 conns, 3x avg) | 657 req/s | 651 req/s | **0.8%** |

Keep-alive overhead is zero because JA4/JA4S are cached per connection. Under connection-per-request load, the module adds less than 1% cost from the single-pass parser plus SHA-256 and msg_callback dispatch.

Full benchmark data and raw output: [docs/BENCHMARK.md](docs/BENCHMARK.md)

## Quick Start

Build the module as a static nginx addon:

```bash
# clone nginx source, then add the module
./configure \
    --add-module=/path/to/ja4 \
    --with-http_ssl_module \
    --with-stream \
    --with-stream_ssl_module \
    ... \
&& make -j$(nproc) \
&& make install
```

Full installation guide with all dependencies: [docs/INSTALL.md](docs/INSTALL.md)

## Configuration

### HTTP

```nginx
http {
    ja4_enable on;

    server {
        listen 443 ssl;
        server_name example.com;

        ssl_certificate      server.crt;
        ssl_certificate_key  server.key;

        location = /ja4 {
            default_type text/plain;
            return 200 "$ssl_ja4\n$ssl_ja4s\n$http_ja4h\n";
        }

        location / {
            proxy_set_header X-JA4 $ssl_ja4;
            proxy_set_header X-JA4H "ja4h_$http_ja4h";
            proxy_pass http://upstream;
        }
    }
}
```

### Stream

```nginx
stream {
    ja4_stream_enable on;

    log_format stream_main
        '$remote_addr [$time_local] '
        '$protocol $status '
        'bytes_sent=$bytes_sent bytes_received=$bytes_received '
        'session_time=$session_time '
        'ja4=$ssl_ja4 ja4s=$ssl_ja4s';

    access_log /var/log/nginx/stream-access.log stream_main;

    server {
        listen 51821 ssl;
        ssl_certificate     /path/to/cert.pem;
        ssl_certificate_key /path/to/key.pem;
        proxy_pass upstream:51821;
    }
}
```

> **Note:** `proxy_set_header` and `add_header` are **not available** in `stream {}` context. JA4 data can only be logged, not forwarded as headers to the upstream.

## Directives

| Directive | Context | Default | Description |
|---|---|---|---|
| `ja4_enable` | http, server | on | Enable JA4/JA4S/JA4H computation |
| `ja4_debug_enable` | http | off | Expose `$ssl_ja4_r` / `$ssl_ja4_o` |
| `ja4_stream_enable` | stream, server | on | Enable JA4/JA4S in stream context |
| `ja4_stream_debug_enable` | stream | off | Expose `$ssl_ja4_r` / `$ssl_ja4_o` in stream |

## Build Variants

Works in all three modes:

* Static module (`--add-module`)
* Dynamic module (`.so`)
* OpenResty addon

No additional external dependencies. No nginx core modifications. No OpenSSL patches.

## Docs

* [INSTALL.md](docs/INSTALL.md) — Full installation guide
* [BENCHMARK.md](docs/BENCHMARK.md) — Benchmark methodology and raw output
* [CHANGES.md](CHANGES.md) — Changelog
