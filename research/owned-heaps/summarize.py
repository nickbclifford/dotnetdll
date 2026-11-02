#!/usr/bin/env python3
"""Retain compact measured observations from the raw /tmp logs."""
import json
from pathlib import Path
import re
import sys

logs = Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/dotnetdll-measurements')
here = Path(__file__).resolve().parent

def contents(name):
    return (logs / name).read_text()

def duration(name):
    m = re.search(r'finished in ([\d.]+)s', contents(name))
    if not m:
        raise ValueError(name)
    return float(m[1])

def criterion(name):
    result, current = {}, None
    for line in contents(name).splitlines():
        if line.startswith('parse/'):
            current = line.split()[0]
        m = re.search(r'time:\s+\[([\d.]+) (µs|ms) ([\d.]+) \2 ([\d.]+) \2\]', line)
        if m and current:
            scale = 0.001 if m[2] == 'µs' else 1
            result[current] = {'low_ms': float(m[1])*scale, 'estimate_ms': float(m[3])*scale, 'high_ms': float(m[4])*scale}
    return result

result = {
    'date': '2026-11-02',
    'baseline_commit': 'ddab300e9f2353ebbe510f14c1ada2da856392f4',
    'consumer_commit': '893d7f8ae89f024b91450af5150a8a205540efca',
    'branch': 'miri-owned-heaps',
    'msrv': '1.85.1',
    'miri_toolchain': 'nightly-2026-05-27',
    'miri_rustc': '1.98.0-nightly d1fc603d1788cc3c0eebdb94a45a61c4f33b1674',
    'miriflags': '-Zmiri-tree-borrows -Zmiri-disable-isolation -Zmiri-ignore-leaks',
    'support_sha256': '720120f3049d58e6a62a4e3e64e95fb8fb13bdc94fbf2ec5cb5555e788596829',
    'corelib_sha256': '22abea031395740f763f1db8e383a760f5a7071d6cfb86c618634b6c6eba94c9',
    'miri_consumer_seconds': {key: duration(key+'.log') for key in ['before-p00','before-batch2','after-p00','after-batch2']},
    'miri_small_fixture_seconds': duration('miri-small-fixture.log'),
    'miri_direct_parse_seconds': {},
    'micro_reads_seconds': {},
    'callgrind_three_captured_calls': {},
    'criterion_final_corelib': criterion('criterion-combined-corelib.log'),
    'criterion_final_support': criterion('criterion-combined-support.log'),
    'criterion_baseline_corelib': criterion('criterion-steady-baseline.log'),
    'criterion_eager_repeats': {label: criterion('criterion-eager-'+label+'.log') for label in ['baseline','baseline-repeat','combined']},
    'native_support_allocation_instrumented_repeats': contents('native-final.txt'),
    'native_class_allocation_instrumented': contents('native-classes.txt'),
    'final_requested_allocation_observations': contents('combined-memory-native.txt'),
    'rss_observations': contents('corelib-rss.txt'),
    'input_inventory': {label: contents(label+'-inventory.txt') for label in ['support','corelib','consumer-before','consumer-after']},
    'consumer_native_test_results': {},
    'full_suite_results': re.findall(r'test result: ok\..*', contents('combined-final-suite.log')),
}
for label, name in [('A-both', 'v2-class-all.log'),('A-strings','v2-class-strings.log'),('A-blobs','v2-class-blobs.log'),('C-split','v2-class-split.log'),('A+D','ranges-miri.log')]:
    result['miri_direct_parse_seconds'][label] = float(re.search(r'parse ([\d.]+)s',contents(name))[1])
for n in [0,600,1500]:
    m = re.search(r'reads=([\d.]+)(ms|s)', contents('micro-'+str(n)+'.log'))
    result['micro_reads_seconds'][n] = float(m[1]) * (0.001 if m[2]=='ms' else 1)
for path in sorted(logs.glob('*instructions.log')):
    m = re.search(r'Collected\s*:\s*(\d+)', path.read_text())
    if m:
        count = int(m[1])
        result['callgrind_three_captured_calls'][path.stem] = {'total': count, 'per_call': count/3}
for label in ['assemblies','vm']:
    result['consumer_native_test_results'][label] = re.findall(r'test result: ok\..*', contents('consumer-final-native-'+label+'.log'))
(here/'results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result['miri_consumer_seconds']))
