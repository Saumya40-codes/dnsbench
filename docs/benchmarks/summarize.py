import argparse
import json
from pathlib import Path
import statistics


def median_metric(runs, key):
    values = [
        latency[key] / 1_000_000
        for run in runs
        for latency in run['summary']['latencies']
        if latency['population'] == 'NOERROR with answers' and latency[key] is not None
    ]
    return f'{statistics.median(values):.3f}' if values else 'n/a'


def summarize(data):
    measured = [run for run in data['runs'] if run['phase'] == 'measured']
    providers = list(dict.fromkeys(run['provider'] for run in data['runs']))
    for query_type in ['A', 'AAAA']:
        print(f'### {query_type}\n')
        print('| Provider | p50 ms | p95 ms | p99 ms | Response QPS | Replies | Timeouts | SERVFAIL | Rejected |')
        print('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |')
        for provider in providers:
            runs = [run for run in measured
                    if run['provider'] == provider and run['query_type'] == query_type]
            if not runs:
                print(f'| {provider} | n/a | n/a | n/a | n/a | No measured runs | n/a | n/a | n/a |')
                continue
            if {run['round'] for run in runs} != set(range(1, data['rounds'] + 1)):
                raise ValueError(f'Incomplete rounds for {provider} {query_type}')
            for run in runs:
                summary = run['summary']
                expected = data['measured_queries_per_run']
                if run['exit_code'] != 0 or summary['sent'] != expected:
                    raise ValueError(f'Incomplete run: {run["output_file"]}')
                if summary['sent'] != summary['responses'] + summary['timeouts'] + summary['socket_errors']:
                    raise ValueError(f'Inconsistent accounting: {run["output_file"]}')
            replies = sum(run['summary']['responses'] for run in runs)
            sent = sum(run['summary']['sent'] for run in runs)
            timeouts = sum(run['summary']['timeouts'] for run in runs)
            servfail = sum(run['summary']['rcodes'][2] for run in runs)
            rejected = sum(run['summary']['rejected_mismatched'] + run['summary']['rejected_malformed']
                           for run in runs)
            qps = statistics.median(run['summary']['responses'] /
                                    (run['summary']['elapsed_ns'] / 1_000_000_000) for run in runs)
            percentiles = ' | '.join(median_metric(runs, key)
                                      for key in ['p50_ns', 'p95_ns', 'p99_ns'])
            print(f'| {provider} | {percentiles} | {qps:.2f} | {replies}/{sent} | '
                  f'{timeouts} | {servfail} | {rejected} |')
        print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Summarize dnsbench resolver comparison results.')
    parser.add_argument('results', type=Path, help='Path to results.json from run.py')
    args = parser.parse_args()
    summarize(json.loads(args.results.read_text()))
