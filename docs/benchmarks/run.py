import argparse
import datetime
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile
import time

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description='Compare five public DNS resolvers with dnsbench.')
parser.add_argument('--output', type=Path, default=Path(tempfile.gettempdir()) /
    datetime.datetime.now(datetime.timezone.utc).strftime('dnsbench-comparison-%Y-%m-%dT%H%M%SZ'),
    help='New directory for raw logs and results.json; must not already exist')
args = parser.parse_args()
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
snapshots = Path(tempfile.mkdtemp(prefix='dnsbench-comparison-'))
binary = root / 'target/release/dns-bench'
workload = root / 'docs/benchmarks/domains.txt'
providers = [
    ('Cloudflare', 'cloudflare', '1.1.1.1'),
    ('Google', 'google', '8.8.8.8'),
    ('Quad9', 'quad9', '9.9.9.9'),
    ('OpenDNS', 'opendns', '208.67.222.222'),
    ('AdGuard unfiltered', 'adguard', '94.140.14.140'),
]
metadata = {
    'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
    'workload_sha256': hashlib.sha256(workload.read_bytes()).hexdigest(),
    'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
    'system': f'{platform.system()} {platform.release()} {platform.machine()}',
    'location': 'Unspecified', 'connection': 'Unspecified', 'execution': 'native release binary',
    'workers': 4, 'threads': 2, 'max_in_flight': 32, 'timeout': '2s',
    'measured_queries_per_run': 1000, 'rounds': 3,
    'warmup_queries_per_provider_and_type': 100,
    'seeds': [42, 43, 44], 'runs': [],
}

def run(provider, query_type, phase, round_number, count, seed):
    name, slug, ip = provider
    label = f'{query_type.lower()}-{phase}-{round_number}-{slug}'
    snapshot = snapshots / f'{label}.jsonl.zst'
    relative_command = ['./target/release/dns-bench', '--server', ip,
        '--domains', 'docs/benchmarks/domains.txt', '--type', query_type,
        '--queries', str(count), '--workers', '4', '--threads', '2',
        '--max-in-flight', '32', '--timeout', '2s', '--shuffle', '--seed', str(seed),
        '--results-file', str(snapshot)]
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = subprocess.run(relative_command, cwd=root, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, timeout=100)
    (output / f'{label}.txt').write_text(result.stdout)
    if not snapshot.exists():
        raise RuntimeError(f'{label} did not save results: {result.stdout}')
    decoded = subprocess.check_output(['zstd', '-dc', str(snapshot)], text=True)
    header = json.loads(decoded.splitlines()[0])
    entry = {'provider': name, 'slug': slug, 'address': ip, 'query_type': query_type,
        'phase': phase, 'round': round_number, 'seed': seed, 'started_utc': started,
        'exit_code': result.returncode, 'command': relative_command,
        'output_file': f'{label}.txt', 'summary': header}
    metadata['runs'].append(entry)
    (output / 'results.json').write_text(json.dumps(metadata, indent=2) + '\n')
    latency = next(x for x in header['latencies'] if x['population'] == 'NOERROR with answers')
    p50 = latency['p50_ns']
    print(f'{label}: {header["responses"]}/{header["sent"]} replies, '
        f'{header["timeouts"]} timeouts, p50={None if p50 is None else p50 / 1e6}ms', flush=True)
    time.sleep(0.5)
    return header['responses'] > 0

for query_type in ['A', 'AAAA']:
    reachable = {}
    for provider in providers:
        reachable[provider[1]] = run(provider, query_type, 'warmup', 0, 100, 42)
    for round_number, seed in enumerate(metadata['seeds'], 1):
        offset = ((round_number - 1) * 2) % len(providers)
        order = providers[offset:] + providers[:offset]
        for provider in order:
            if reachable[provider[1]]:
                run(provider, query_type, 'measured', round_number, 1000, seed)
metadata['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
(output / 'results.json').write_text(json.dumps(metadata, indent=2) + '\n')
print(f'Complete. Results: {output}; snapshots: {snapshots}', flush=True)
