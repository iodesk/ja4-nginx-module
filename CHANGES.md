# CHANGES

## v0.1.1

Stream module build and linkage completion.

### Stream Module

* **`config` file migrated to new-style format** for nginx 1.30.4 build system. Old-style `HTTP_MODULES` / `STREAM_MODULES` / `NGX_ADDON_SRCS` variables are no longer supported. The `config` now uses `ngx_module_type` + `. auto/module` with separate registrations for HTTP and STREAM module types.

* **Shared SSL ex-data index between HTTP and stream modules.** `ngx_http_ja4_ssl_index` is now declared `extern` in `ngx_http_ja4.h` so both HTTP and stream modules read/write the same per-connection TLS context. Stream variable handler (`$ssl_ja4`, `$ssl_ja4s`) now resolves correctly.

* **`ngx_http_ja4_msg_callback` visible across modules.** Forward declaration changed from `static` to external linkage so the stream module can link against the shared callback function.

---

## v0.1.0

Build based on **nginx 1.30.4**. This document records every change introduced by the `ja4/` addon module.

### nginx Core Changes

**No nginx core files are modified.**

The JA4 module is a pure addon. It never touches any file under `src/`. All hooks go through public OpenSSL APIs (`SSL_CTX_set_msg_callback`, `SSL_get_ex_new_index`, `SSL_set_ex_data`, `SSL_get_ex_data`) and standard nginx module APIs (`ngx_http_module_t`, `ngx_http_add_variable`, ...).

Core files that are not modified (listed for reference only):

* `src/event/ngx_event_openssl.c`
* `src/event/ngx_event_openssl.h`
* `src/http/ngx_http_request.c`
* `src/http/ngx_http_ssl_module.c`
* `src/http/modules/ngx_http_ssl_module.c`

The build only adds the `ja4/` addon directory (via `--add-module` / `--add-dynamic-module`); no core build files are touched.

### New Features

* **Stream support** – JA4 fingerprints are now usable inside `stream {}` contexts. The module registers a Stream‑module that installs the same OpenSSL message callback via `ngx_stream_ssl_module` and exposes `$ssl_ja4`, `$ssl_ja4s`, `$ssl_ja4_r`, `$ssl_ja4_o` as stream variables. No core or OpenSSL patches are required.

  One standalone nginx module computing three fingerprints:

  * `$ssl_ja4`  JA4 TLS ClientHello fingerprint (36 chars canonical). Example: `t13d1516h2_8daaf6152771_e5627efa2ab1`
  * `$ssl_ja4s`  JA4S TLS ServerHello fingerprint. Example: `t130200_1302_a56c5b993250`
  * `$http_ja4h`  JA4H HTTP request fingerprint (`A_B_C_D`). Example: `ge11cr06enus_8c2f9ef95269_d23bf79698dc_69e42fa741fe`
  * `$ssl_ja4_r`, `$ssl_ja4_o`  raw JA4 variants, exposed only when `ja4_debug_enable on;` (directive).

  * No nginx core patch, no OpenSSL patch.
  * OpenSSL `SSL_CTX_set_msg_callback` installed per server; raw ClientHello / ServerHello parsed directly.
  * QUIC / HTTP/3 detection: first char `q` when the connection is QUIC (needs `--with-http_v3_module` + OpenSSL 3.x with QUIC).
  * New directive: `ja4_enable on | off` (default `on`, context `http`, `server`). One switch controls the JA4 (TLS), JA4S (ServerHello) and JA4H (HTTP) pipelines.
  * New directive: `ja4_debug_enable on | off` (default `off`, context `http`, `server`). When on, exposes the debug variables `$ssl_ja4_r` and `$ssl_ja4_o`; when off they return `not_found`.
  * JA4H computed per HTTP request from `r->headers_in` (original header order for section B, sorted cookie names/values for C/D, Accept-Language for A).
  * JA4S computed from the ServerHello sent by this server (OpenSSL msg_callback `write_p=1`); single server cipher plus server extension list.
  * Modular architecture: one module, three independent pipelines (`tls_parser`/`tls_builder`, `tls_server_parser`/`tls_server_builder`, `http_parser`/`http_builder`) sharing one crypto layer (SHA-256).
  * Self-contained SHA-256  no extra link dependencies.
  * OpenSSL 1.1.1+ for TLS/TCP; QUIC requires OpenSSL 3.x.
  * Static or dynamic build (`--add-module` / `--add-dynamic-module`).

  Limitations:

  * QUIC/HTTP3 (`q`) only works when nginx is built with `--with-http_v3_module` and a QUIC-capable OpenSSL 3.x; otherwise the first char stays `t` (a non-QUIC build never sees QUIC connections, correct behavior).
  * DTLS (`d`) is recognized in code, but this nginx build has no DTLS listener path; only TLS/TCP and QUIC are reachable.

### Bug Fixes

* **Bug: TLS version always `00` (supported_versions offset)**

  The `supported_versions` (0x002b) extension loop started at offset `i = 2`, but the extension body is `[1-byte vector length][2*n ProtocolVersion list]`  the first entry starts at offset `1`. The first version (e.g. `0304` for TLS 1.3) was skipped and a wrong value (e.g. `0x0403`) was taken, producing `t00` instead of `t13`.

  Fix: the loop starts at `i = 1`. File: `ja4/src/ngx_http_ja4_tls_parser.c`.

* **Bug: `$ssl_ja4`, `$ssl_ja4_r`, `$ssl_ja4_o` returned identical output**

  The variable array initializer placed `NGX_HTTP_VAR_NOCACHEABLE` in the `data` field position and the selector (0/1/2) in the `flags` position. Because `ngx_http_variable_t` lays out `data` before `flags`, every variable received `data = 2` (the value of `NGX_HTTP_VAR_NOCACHEABLE`), so the handler always selected `ja4_o`.

  Fix: swapped the fields  selector (0/1/2) in `data`, `NGX_HTTP_VAR_NOCACHEABLE` in `flags`. File: `ja4/src/ngx_http_ja4_module.c`.

* **Bug: JA4S version always TLS 1.2 (`t12`)**

  The ServerHello parser read the version from the legacy version field, which is `0x0303` even for TLS 1.3 handshakes. The real negotiated version lives in the `supported_versions` (0x002b) extension, whose ServerHello form is a single 2-byte `ProtocolVersion` (no length prefix, unlike ClientHello).

  Fix: when `supported_versions` is present in the ServerHello, read the negotiated version directly from its 2-byte value. File: `ja4/src/ngx_http_ja4_tls_server_parser.c`.

### Base Version

* nginx 1.30.4 (unmodified core).
* openssl 4 (unmodified).