# ja4-nginx-module

JA4 TLS fingerprint as a standalone nginx module.

Zero changes to nginx core. Zero changes to OpenSSL. Just drop it in and build.

The module hooks into OpenSSL's message callback (`SSL_CTX_set_msg_callback`) on each server's existing `SSL_CTX`, parses the raw TLS ClientHello, and computes the JA4 fingerprint per the [FoxIO JA4 specification](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md).

```text
ngx_http_ja4
   |          |          |
   v          v          v
tls_parser  tls_server_ http_parser
 (JA4)      parser      (JA4H)
            (JA4S)
   v          v          v
   +----------+----------+
              v
           crypto
```

## Why ngx_http_ja4

**Zero core patch.** No fork. No OpenSSL patch. The module installs itself through public nginx and OpenSSL APIs only.

**Three fingerprints, one module.** JA4 (TLS ClientHello), JA4S (ServerHello), and JA4H (HTTP) computed from a single module with three independent pipelines sharing one SHA-256 crypto layer.

**Computed once, cached forever.** JA4 and JA4S are parsed at ClientHello time, once per connection, and cached in SSL ex-data. JA4H is computed once per HTTP request and cached in the request context. Variable reads return a pointer with zero parsing, zero hashing, zero copying.

**QUIC ready.** Automatic HTTP/3 detection. First character becomes `q` when the connection is QUIC (requires nginx built with `--with-http_v3_module`).

**Minimal surface.** Self-contained SHA-256, no extra link dependencies. Static build via `--add-module`.

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
    ... \
&& make -j$(nproc) \
&& make install
```

Full installation guide with all dependencies: [docs/INSTALL.md](docs/INSTALL.md)

## Configuration

Enable per server block:

```nginx
server {
    listen 443 ssl;

    ssl_certificate      server.crt;
    ssl_certificate_key  server.key;

    ja4_enable on;

    # expose fingerprints
    location = /ja4 {
        default_type text/plain;
        return 200 "$ssl_ja4\n$ssl_ja4s\n$http_ja4h\n";
    }
}
```

Available variables:

| Variable | Scope | Description |
|---|---|---|
| `$ssl_ja4` | connection | JA4 fingerprint (e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`) |
| `$ssl_ja4s` | connection | JA4S fingerprint (server hello) |
| `$http_ja4h` | request | JA4H fingerprint (HTTP, format `A_B_C_D`) |
| `$ssl_ja4_r` | connection | Raw JA4 (requires `ja4_debug_enable on`) |
| `$ssl_ja4_o` | connection | Raw JA4 order (requires `ja4_debug_enable on`) |

Directives:

| Directive | Context | Default | Description |
|---|---|---|---|
| `ja4_enable` | server | on | Enable/disable JA4 computation |
| `ja4_debug_enable` | http | off | Expose debug variables `$ssl_ja4_r` / `$ssl_ja4_o` |

Full sample config: [sample-nginx.conf](sample-nginx.conf)

## Build Variants

Works in all three modes:

* Static module (`--add-module`)
* Dynamic module (`.so`)
* OpenResty addon

No additional external dependencies. No nginx core modifications. No OpenSSL patches.

## Docs

* [INSTALL.md](docs/INSTALL.md)  Full installation guide
* [BENCHMARK.md](docs/BENCHMARK.md)  Benchmark methodology and raw output
* [CHANGES.md](docs/CHANGES.md)  Changelog
