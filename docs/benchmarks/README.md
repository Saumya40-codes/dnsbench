# Public resolver comparison

Measured on 2026-10-31, 05:41:14 to 05:43:48 UTC, from one Linux x86_64 host with an Intel Core i5-12450H. City, ISP, and connection type were not recorded. These results describe this host's network path at that time and are not a global provider ranking.

## Setup

- Native release binary, Rust 1.95.0, built with `cargo build --release --locked`.
- [100 unique names](domains.txt) spanning developer tools, cloud/CDN services, media, universities, public institutions, and regional sites. Includes apex and `www` names from some of the same zones.
- A and AAAA questions, both sent over IPv4 UDP to port 53. No EDNS, retries, or TCP fallback.
- 4 workers, automatic Tokio sizing (12 runtime threads recorded), 32 outstanding queries, 2-second timeout.
- One 100-query warmup per provider and query type, followed by three 1,000-query measured runs. Each measured run queries every name ten times.
- Each run is sequential relative to other providers. Provider order rotates by two positions each round. Shuffle seeds are 42, 43, and 44, shared across providers in each round.
- All A runs precede AAAA runs. Warmups are excluded from the tables. Resolver caches are not flushed or controlled, and the host is not isolated from other activity.

Resolver addresses were checked against provider documentation:

| Provider | Address | Service |
| --- | --- | --- |
| [Cloudflare](https://developers.cloudflare.com/1.1.1.1/ip-addresses/) | `1.1.1.1` | Standard |
| [Google](https://developers.google.com/speed/public-dns/docs/using) | `8.8.8.8` | Public DNS |
| [Quad9](https://docs.quad9.net/services/) | `9.9.9.9` | Secure, threat blocking |
| [OpenDNS](https://www.opendns.com/setupguide/) | `208.67.222.222` | Standard |
| [AdGuard](https://adguard-dns.io/en/public-dns.html) | `94.140.14.140` | Non-filtering |

These services have different filtering and validation policies. This workload does not evaluate those policies or answer correctness.

## Results

Latency columns are medians of the three run-level percentiles for the `NOERROR with answers` population. They are not percentiles pooled across runs, and exclude empty answers, DNS errors, and timeouts. Response QPS is the median achieved response rate, including final draining, not a measurement of maximum resolver capacity.

Replies, timeouts, SERVFAIL, and rejected-packet counts are summed across the three runs. Replies include valid DNS error responses. Rejected packets are separate from query outcomes and can include late responses whose pending entry has expired. There were no malformed packets or socket errors in the measured runs.

### A

| Provider | p50 ms | p95 ms | p99 ms | Response QPS | Replies | Timeouts | SERVFAIL | Rejected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Cloudflare | 12.132 | 224.002 | 308.281 | 357.01 | 2986/3000 | 14 | 25 | 0 |
| Google | 22.790 | 258.736 | 441.450 | 210.33 | 2910/3000 | 90 | 0 | 20 |
| Quad9 | 24.232 | 233.701 | 288.883 | 421.24 | 2981/3000 | 19 | 30 | 0 |
| OpenDNS | 17.236 | 255.721 | 567.280 | 296.55 | 2992/3000 | 8 | 29 | 2 |
| AdGuard unfiltered | 71.959 | 300.417 | 580.387 | 179.14 | 2965/3000 | 35 | 19 | 15 |

### AAAA

| Provider | p50 ms | p95 ms | p99 ms | Response QPS | Replies | Timeouts | SERVFAIL | Rejected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Cloudflare | 13.214 | 67.437 | 298.320 | 362.38 | 2982/3000 | 18 | 26 | 2 |
| Google | 22.479 | 101.777 | 393.216 | 204.18 | 2925/3000 | 75 | 4 | 20 |
| Quad9 | 24.510 | 75.104 | 286.261 | 422.80 | 2986/3000 | 14 | 30 | 0 |
| OpenDNS | 20.005 | 129.827 | 302.252 | 316.47 | 2991/3000 | 9 | 26 | 2 |
| AdGuard unfiltered | 73.925 | 301.728 | 520.880 | 160.31 | 2938/3000 | 62 | 32 | 12 |

## Observations

Cloudflare had the lowest median A and AAAA response latency in this sample. Tail latency, achieved throughput, and timeouts varied across providers and rounds, so p50 alone does not describe the run.

Separate sanity checks used three dig queries per provider and query type for `example.com`. Error-case checks reproduced Google's SERVFAIL for `www.gov.in` after 2.111 to 2.247 seconds in all three attempts. AdGuard's `nic.in` checks returned after about 2.15 seconds twice and timed out once with a 5-second wait. These checks were performed after the benchmark and are excluded from its tables.

Additional alternating single-domain checks showed variable AdGuard latency in both dnsbench and dig. Some transient benchmark timeouts did not reproduce afterward. Counts were retained as observed. A timeout means no acceptable response arrived within the configured 2-second deadline; it does not establish packet loss.

## Reproduce

Requires Rust, Python 3, and the `zstd` command-line tool. The runner uses Tokio's automatic thread sizing. Run from the repository root:

```sh
cargo build --release --locked
python3 docs/benchmarks/run.py --output /tmp/dnsbench-comparison
python3 docs/benchmarks/summarize.py /tmp/dnsbench-comparison/results.json
```

Choose a new output directory for each comparison. Without `--output`, the runner creates a directory under the system temporary directory. It saves raw logs and snapshot headers in `results.json`, including exact commands, timestamps, counts, histogram percentiles, and binary/workload hashes. Full compressed snapshots are kept in a separate temporary directory whose path is printed on completion. The default last-run snapshot is not overwritten.

This comparison used 30 measured runs and 10 warmups. Generated logs and JSON results are not committed. The runner checks reachability during warmup and skips measured runs for a provider/type with no warmup responses. All five providers were reachable in this comparison. Repeating the commands reproduces the procedure, not the same network timings.
