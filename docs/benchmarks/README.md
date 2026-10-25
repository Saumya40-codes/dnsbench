# Public resolver comparison

Measured on 2026-10-25, 07:00:47 to 07:03:04 UTC, from one Linux x86_64 host with an Intel Core i5-12450H. City, ISP, and connection type were not recorded. These results describe this host's network path at that time and are not a global provider ranking.

## Setup

- Native release binary, Rust 1.95.0, source commit `7e455bf2cb2eb8f98104d957484e9f431778dccd`.
- [100 unique names](domains.txt) spanning developer tools, cloud/CDN services, media, universities, public institutions, and regional sites. Includes apex and `www` names from some of the same zones.
- A and AAAA questions, both sent over IPv4 UDP to port 53. No EDNS, retries, or TCP fallback.
- 4 workers, 2 runtime threads, 32 outstanding queries, 2-second timeout.
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
| Cloudflare | 8.495 | 23.937 | 149.422 | 1410.14 | 3000/3000 | 0 | 30 | 0 |
| Google | 26.640 | 131.858 | 423.887 | 255.62 | 2968/3000 | 32 | 1 | 16 |
| Quad9 | 20.972 | 214.434 | 536.347 | 351.45 | 2998/3000 | 2 | 30 | 0 |
| OpenDNS | 16.179 | 143.131 | 437.518 | 393.15 | 2995/3000 | 5 | 28 | 0 |
| AdGuard unfiltered | 69.927 | 301.990 | 619.708 | 155.30 | 2919/3000 | 81 | 29 | 25 |

### AAAA

| Provider | p50 ms | p95 ms | p99 ms | Response QPS | Replies | Timeouts | SERVFAIL | Rejected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Cloudflare | 8.110 | 21.201 | 158.466 | 489.70 | 2998/3000 | 2 | 28 | 2 |
| Google | 31.457 | 103.481 | 409.207 | 277.38 | 2970/3000 | 30 | 1 | 16 |
| Quad9 | 19.956 | 64.258 | 389.808 | 668.36 | 2993/3000 | 7 | 30 | 0 |
| OpenDNS | 15.983 | 76.218 | 329.253 | 314.81 | 2980/3000 | 20 | 14 | 0 |
| AdGuard unfiltered | 69.796 | 309.068 | 1043.857 | 148.81 | 2939/3000 | 61 | 22 | 25 |

## Observations

Cloudflare had the lowest median A and AAAA response latency in this sample. OpenDNS was next by p50. Tail latency and timeouts varied substantially, so p50 alone does not describe the run.

The 2-second deadline matters. Separate [dig spot checks](2026-10-25/diagnostics.txt) observed a Google SERVFAIL for `www.gov.in` after 2.192 seconds and an AdGuard empty answer for `nic.in` after 2.157 seconds. Those checks occurred after the benchmark and are not included in its metrics. A timeout means no acceptable response arrived within the deadline; it does not establish packet loss.

## Reproduce

Requires Rust, Python 3, and the `zstd` command-line tool. Run from the repository root:

```sh
cargo build --release --locked
python3 docs/benchmarks/run.py --output /tmp/dnsbench-comparison
python3 docs/benchmarks/summarize.py /tmp/dnsbench-comparison/results.json
```

Choose a new output directory for each comparison. The runner saves raw logs and snapshot headers in `results.json`, including exact commands, timestamps, counts, histogram percentiles, and binary/workload hashes. Full compressed snapshots are kept in a separate temporary directory whose path is printed on completion. The default last-run snapshot is not overwritten.

The published [raw logs and summaries](2026-10-25/) include all 30 measured runs and all 10 warmups. The runner checks reachability during warmup and skips measured runs for a provider/type with no warmup responses. All five providers were reachable in this comparison. Repeating the commands reproduces the procedure, not the same network timings.
