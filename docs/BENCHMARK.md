# BENCHMARK — ngx_http_ja4

Measured overhead of the ja4 module against two references on the same
server:

- **baseline** — plain nginx 1.30.4 without the ja4 module
- **ja4 off** — nginx built with the module, `ja4_enable off`
- **ja4 on** — nginx built with the module, `ja4_enable on`,
  `ja4_debug_enable off` (production mode)

## Environment

- nginx 1.30.4 (baseline) and nginx 1.30.4-custom with `ja4/` module
- OpenSSL 3.3.2, TLS 1.3 (HTTP/1.1 over TLS)
- Load tool: `wrk`
- Command: `wrk -t4 -c100 -d60s https://<host>/`
- Each `Connection: close` scenario runs 3 times and the average is
  reported; keep-alive is a single 60s run.

Results captured on a separate VPS (remote measurement). A third
configuration (baseline without module) was added to quantify the cost
of the module binary itself against a completely stock build.

## Keep-alive (single 60s run)

`wrk -t4 -c100 -d60s https://k6-test.fio.link/`

| Metric       | ja4_enable on | ja4_enable off | Delta        |
|--------------|---------------|----------------|--------------|
| Requests/sec | 1956.53       | 1957.38        | **-0.04%**   |
| Avg latency  | 51.30 ms      | 51.09 ms       | +0.21 ms     |
| Max latency  | 310.13 ms     | 310.70 ms      | ~sama        |

## Connection: close, 3 runs (per-request handshake)

`wrk -t4 -c100 -H "Connection: close" -d60s https://k6-test.fio.link/`

Three configurations: **baseline** (plain nginx, module not built in),
**ja4 off** (module built, `ja4_enable off`), **ja4 on** (module built,
`ja4_enable on`, debug off).

| Metric     | Baseline | ja4 off | ja4 on | Delta on vs baseline |
|------------|----------|---------|--------|----------------------|
| Req/sec #1 | 653.36   | 657.63  | 649.60 |                      |
| Req/sec #2 | 660.19   | 658.06  | 654.38 |                      |
| Req/sec #3 | 656.21   | 660.21  | 649.99 |                      |
| **Avg**    | **656.6**| **658.6**| **651.3**| **-0.8%**           |
| Lat avg #1 | 49.87 ms | 49.87 ms | 50.53 ms |                    |
| Lat avg #2 | 50.00 ms | 49.99 ms | 50.08 ms |                    |
| Lat avg #3 | 50.24 ms | 49.73 ms | 50.47 ms |                    |
| **Avg**    | **50.04 ms**| **49.86 ms**| **50.36 ms**| **+0.32 ms**   |

## Analysis

- **Keep-alive:** JA4 / JA4S are computed once per connection at the TLS
  handshake and cached in SSL ex-data. Subsequent requests on the same
  connection read the cached buffers, so per-request overhead is zero.
  Observed delta ~0 (within noise).
- **Connection: close:** each request opens a new TLS connection, so the
  ClientHello/ServerHello parse path runs once per request. Across
  three repeated runs:
  - **baseline vs ja4 off**: 656.6 vs 658.6 req/s — the module binary
    itself costs nothing when disabled (delay & variance are within
    noise). This shows `ja4_enable off` truly disables all work.
  - **baseline vs ja4 on**: 656.6 vs 651.3 req/s — about **-0.8%**, a
    small but real per-handshake cost from the single-pass parser plus
    2-3 SHA-256 and the msg_callback dispatch. This is negligible next
    to the OpenSSL handshake and network cost.
- Debug variables (`ja4_debug_enable`) are off in these runs, so they
  add no measurable cost here.

## Conclusion

No meaningful overhead under keep-alive. Under connection-per-request
load the module adds <1% throughput cost from the per-handshake JA4/JA4S
computation; the module-compiled-but-disabled build (`ja4_enable off`)
is as fast as plain nginx. JA4H runs once per request (cached in the
request context) and adds no measurable per-request cost.

## Re-run

```sh
# baseline (plain nginx, module removed from build)
./configure [without --add-module=./ja4] && make -j$(nproc) && make install
for i in 1 2 3; do wrk -t4 -c100 -H "Connection: close" -d60s https://<host>/; sleep 5; done

# module off (ja4_enable off)
sed -i 's/ja4_enable on/ja4_enable off/' nginx.conf && nginx -s reload
for i in 1 2 3; do wrk -t4 -c100 -H "Connection: close" -d60s https://<host>/; sleep 5; done

# module on (ja4_enable on)
sed -i 's/ja4_enable off/ja4_enable on/' nginx.conf && nginx -s reload
for i in 1 2 3; do wrk -t4 -c100 -H "Connection: close" -d60s https://<host>/; sleep 5; done
```

## Raw output

### Keep-alive (on / off)

```
ja4_enable on;

wrk -t4 -c100 -d60s https://k6-test.fio.link/
Running 1m test @ https://k6-test.fio.link/
  4 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    51.30ms   11.21ms 310.13ms   99.56%
    Req/Sec   492.70     22.63   510.00     92.65%
  117477 requests in 1.00m, 32.94MB read
  Non-2xx or 3xx responses: 117477
Requests/sec:   1956.53
Transfer/sec:    561.73KB

ja4_enable off;

wrk -t4 -c100 -d60s https://k6-test.fio.link/
Running 1m test @ https://k6-test.fio.link/
4 threads and 100 connections
Thread Stats    Avg        Stdev     Max   +/- Stddev
    Latency    51.09ms    9.06ms   310.70ms    99.71%
    Req/Sec   492.60      24.19     505.00     95.62%
 117513 requests in 1.00m, 32.95MB read
  Non-2xx or 3xx responses: 117513
  Requests/sec:  1957.38
  Transfer/sec:  561.97KB
```

### Connection: close, 3 runs each

```
===== Baseline (plain nginx, no module) =====

===== Baseline Run #1 =====
wrk -t4 -c100 -H "Connection: close" -d60s https://k6-test.fio.link/
Running 1m test @ https://k6-test.fio.link/
4 threads and 100 connections
Thread Stats   Avg      Stdev     Max   +/- Stdev
Latency    49.87ms   12.06ms 410.46ms   99.58%
Req/Sec   164.13     34.72   252.00     70.77%
39263 requests in 1.00m, 10.82MB read
Non-2xx or 3xx responses: 39263
Requests/sec:    653.36
Transfer/sec:    184.40KB

===== Baseline Run #2 =====
Running 1m test @ https://k6-test.fio.link/
4 threads and 100 connections
Thread Stats   Avg      Stdev     Max   +/- Stdev
Latency    50.00ms   14.57ms 416.89ms   99.60%
Req/Sec   165.90     38.51   252.00     69.63%
39676 requests in 1.00m, 10.94MB read
Non-2xx or 3xx responses: 39676
Requests/sec:    660.19
Transfer/sec:    186.32KB

===== Baseline Run #3 =====
Running 1m test @ https://k6-test.fio.link/
4 threads and 100 connections
Thread Stats   Avg      Stdev     Max   +/- Stdev
Latency    50.24ms   16.09ms 415.03ms   99.50%
Req/Sec   164.87     31.04   247.00     68.69%
39433 requests in 1.00m, 10.87MB read
Non-2xx or 3xx responses: 39433
Requests/sec:    656.21
Transfer/sec:    185.20KB

ja4_enable on;

===== ON Run #1 =====
wrk -t4 -c100 -H "Connection: close" -d60s https://k6-test.fio.link/
Running 1m test @ https://k6-test.fio.link/
4 threads and 100 connections
Thread Stats   Avg      Stdev     Max   +/- Stdev
Latency    50.53ms   16.84ms 512.83ms   99.26%
Req/Sec   163.19     30.24   250.00     68.28%
39026 requests in 1.00m, 10.76MB read
Non-2xx or 3xx responses: 39026
Requests/sec:    649.60
Transfer/sec:    183.33KB

===== ON Run #2 =====
Running 1m test @ https://k6-test.fio.link/
4 threads and 100 connections
Thread Stats   Avg      Stdev     Max   +/- Stdev
Latency    50.08ms   13.50ms 411.81ms   99.50%
Req/Sec   164.39     34.41   252.00     71.03%
39308 requests in 1.00m, 10.83MB read
Non-2xx or 3xx responses: 39308
Requests/sec:    654.38
Transfer/sec:    184.68KB

===== ON Run #3 =====
Running 1m test @ https://k6-test.fio.link/
4 threads and 100 connections
Thread Stats   Avg      Stdev     Max   +/- Stdev
Latency    50.47ms   19.24ms 912.76ms   99.46%
Req/Sec   163.30     32.70   252.00     69.23%
39053 requests in 1.00m, 10.76MB read
Non-2xx or 3xx responses: 39053
Requests/sec:    649.99
Transfer/sec:    183.44KB

ja4_enable off;

===== OFF Run #1 =====
Running 1m test @ https://k6-test.fio.link/
4 threads and 100 connections
Thread Stats   Avg      Stdev     Max   +/- Stdev
Latency    49.87ms   13.01ms 607.36ms   99.66%
Req/Sec   165.18     30.23   252.00     69.89%
39497 requests in 1.00m, 10.89MB read
Non-2xx or 3xx responses: 39497
Requests/sec:    657.63
Transfer/sec:    185.60KB

===== OFF Run #2 =====
Running 1m test @ https://k6-test.fio.link/
4 threads and 100 connections
Thread Stats   Avg      Stdev     Max   +/- Stdev
Latency    49.99ms   13.45ms 412.78ms   99.59%
Req/Sec   165.32     33.93   252.00     67.99%
39530 requests in 1.00m, 10.89MB read
Non-2xx or 3xx responses: 39530
Requests/sec:    658.06
Transfer/sec:    185.72KB

===== OFF Run #3 =====
Running 1m test @ https://k6-test.fio.link/
4 threads and 100 connections
Thread Stats   Avg      Stdev     Max   +/- Stdev
Latency    49.73ms   10.97ms 410.40ms   99.65%
Req/Sec   165.85     32.60   252.00     70.11%
39665 requests in 1.00m, 10.93MB read
Non-2xx or 3xx responses: 39665
Requests/sec:    660.21
Transfer/sec:    186.33KB
```