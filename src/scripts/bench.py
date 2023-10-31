#!/usr/bin/env python3

"""
Compare Botan with OpenSSL using their respective benchmark utils

(C) 2017,2022 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)

TODO
 - Also compare RSA, ECDSA, ECDH
 - Output pretty graphs with matplotlib
"""

import logging
import os
import sys
import optparse # pylint: disable=deprecated-module
import subprocess
import re
import json

def setup_logging(options):
    if options.verbose:
        log_level = logging.DEBUG
    elif options.quiet:
        log_level = logging.WARNING
    else:
        log_level = logging.INFO

    class LogOnErrorHandler(logging.StreamHandler):
        def emit(self, record):
            super().emit(record)
            if record.levelno >= logging.ERROR:
                sys.exit(1)

    lh = LogOnErrorHandler(sys.stdout)
    lh.setFormatter(logging.Formatter('%(levelname) 7s: %(message)s'))
    logging.getLogger().addHandler(lh)
    logging.getLogger().setLevel(log_level)

def run_command(cmd):
    logging.debug("Running '%s'", ' '.join(cmd))

    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True)
    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        logging.error("Running command %s failed ret %d", ' '.join(cmd), proc.returncode)

    return stdout + stderr

def get_openssl_version(openssl):
    output = run_command([openssl, 'version'])

    openssl_version_re = re.compile(r'OpenSSL ([0-9a-z\.]+) .*')

    match = openssl_version_re.match(output)

    if match:
        return match.group(1)
    else:
        logging.warning("Unable to parse OpenSSL version output %s", output)
        return output

def get_botan_version(botan):
    return run_command([botan, 'version']).strip()

HASH_EVP_MAP = {
    # 'AES-128/GCM': 'aes-128-gcm',
    # 'AES-256/GCM': 'aes-256-gcm',
    # 'ChaCha20': 'chacha20',
    # 'SHA-1': 'sha1',
    # 'SHA-256': 'sha256',
    # 'SHA-384': 'sha384',
    # 'SHA-512': 'sha512',
    # 'SHA-3(256)': 'sha3-256',
    }

SIGNATURE_EVP_MAP = {
    'RSA': 'rsa',
}

def run_openssl_bench(openssl, algo):

    logging.info('Running OpenSSL benchmark for %s', algo)

    cmd = [openssl, 'speed', '-seconds', '1', '-mr']

    if algo in HASH_EVP_MAP:
        cmd += ['-evp', HASH_EVP_MAP[algo]]
    elif algo in SIGNATURE_EVP_MAP:
        cmd += [SIGNATURE_EVP_MAP[algo]]
    else:
        cmd += [algo]

    output = run_command(cmd)
    results = []

    if algo in HASH_EVP_MAP:
        buf_header = re.compile(r'\+DT:([a-zA-Z0-9-]+):([0-9]+):([0-9]+)$')
        res_header = re.compile(r'\+R:([0-9]+):[a-zA-Z0-9-]+:([0-9]+\.[0-9]+)$')
        ignored = re.compile(r'\+(H|F):.*')

        result = {}

        for l in output.splitlines():
            if ignored.match(l):
                continue

            if not result:
                match = buf_header.match(l)
                if match is None:
                    logging.error("Unexpected output from OpenSSL %s", l)

                result = {'algo': algo, 'buf_size': int(match.group(3))}
            else:
                match = res_header.match(l)

                result['bytes'] = int(match.group(1)) * result['buf_size']
                result['runtime'] = float(match.group(2))
                result['bps'] = int(result['bytes'] / result['runtime'])
                results.append(result)
                result = {}
    elif algo in SIGNATURE_EVP_MAP:
        # +R1:35086:512:1.02
        # +R2:562312:512:1.02
        signature_ops = re.compile(r'\+R1:([0-9]+):([0-9]+):([0-9]+\.[0-9]+)$')
        verify_ops = re.compile(r'\+R2:([0-9]+):([0-9]+):([0-9]+\.[0-9]+)$')
        ignored = re.compile(r'\+(DTP|F2):.*')

        result = {}

        for l in output.splitlines():
            if ignored.match(l):
                continue

            if match := signature_ops.match(l):
                results.append({
                    'algo': algo,
                    'key_size': int(match.group(2)),
                    'op': 'sign',
                    'ops': int(match.group(1)),
                    'runtime': float(match.group(3))})
            elif match := verify_ops.match(l):
                results.append({
                    'algo': algo,
                    'key_size': int(match.group(2)),
                    'op': 'verify',
                    'ops': int(match.group(1)),
                    'runtime': float(match.group(3))
                })
            else:
                logging.error("Unexpected output from OpenSSL %s", l)

    return results

def run_botan_bench(botan, runtime, buf_sizes, algo):
    cmd = [botan, 'speed', '--format=json', '--msec=%d' % int(runtime * 1000),
           '--buf-size=%s' % (','.join([str(i) for i in buf_sizes])), algo]
    output = run_command(cmd)
    output = json.loads(output)

    return output

def run_botan_signature_bench(botan, runtime, algo):
    cmd = [botan, 'speed', '--format=json', '--msec=%d' % int(runtime * 1000), algo]
    output = run_command(cmd)
    output = json.loads(output)

    results = []
    for verify in output:
        for sign in output:
            if sign['op'] == 'sign' and verify['op'] == 'verify' and verify['algo'] == sign['algo']:
                results.append({
                    'algo': algo,
                    'sig_ops': sign['events'],
                    'sig_runtime': sign['nanos'] / 1000 / 1000 / 1000,
                    'verify_ops': verify['events'],
                    'verify_runtime': verify['nanos'] / 1000 / 1000 / 1000,
                    'key_size': int(re.search(r'RSA-([0-9]+) .*', sign['algo']).group(1)),
                })

    return results

class BenchmarkResult:
    def __init__(self, algo, sizes, openssl_results, botan_results):
        self.algo = algo
        self.results = {}

        def find_result(results, sz):
            for r in results:
                if 'buf_size' in r and r['buf_size'] == sz:
                    return r['bps']
                if 'key_size' in r and r['key_size'] == sz:
                    return (r['sig_ops'], r['verify_ops'])
            raise Exception("Could not find expected result in data")

        for size in sizes:
            self.results[size] = {
                'openssl': find_result(openssl_results, size),
                'botan': find_result(botan_results, size)
            }

    def result_string(self):

        out = ""
        for (k, v) in self.results.items():

            if v['openssl'] > v['botan']:
                winner = 'openssl'
                ratio = float(v['openssl']) / v['botan']
            else:
                winner = 'botan'
                ratio = float(v['botan']) / v['openssl']

            out += "algo %s buf_size % 6d botan % 12d bps openssl % 12d bps adv %s by %.02f\n" % (
                self.algo, k, v['botan'], v['openssl'], winner, ratio)
        return out

def bench_algo(openssl, botan, algo):
    openssl_results = run_openssl_bench(openssl, algo)

    buf_sizes = sorted([x['buf_size'] for x in openssl_results])
    runtime = sum(x['runtime'] for x in openssl_results) / len(openssl_results) / len(buf_sizes)

    botan_results = run_botan_bench(botan, runtime, buf_sizes, algo)

    return BenchmarkResult(algo, buf_sizes, openssl_results, botan_results)

def bench_signature_algo(openssl, botan, algo):
    openssl_results = run_openssl_bench(openssl, algo)

    runtime = sum(x['runtime'] for x in openssl_results) / len(openssl_results)
    botan_results = run_botan_signature_bench(botan, runtime, algo)

    kszs_ossl = {x['key_size'] for x in openssl_results}
    kszs_botan = {x['key_size'] for x in botan_results}

    return BenchmarkResult(algo, kszs_ossl.intersection(kszs_botan), openssl_results, botan_results)

def main(args=None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser()

    parser.add_option('--verbose', action='store_true', default=False, help="be noisy")
    parser.add_option('--quiet', action='store_true', default=False, help="be very quiet")

    parser.add_option('--openssl-cli', metavar='PATH',
                      default='/usr/bin/openssl',
                      help='Path to openssl binary (default %default)')

    parser.add_option('--botan-cli', metavar='PATH',
                      default='/usr/bin/botan',
                      help='Path to botan binary (default %default)')

    (options, args) = parser.parse_args(args)

    setup_logging(options)

    openssl = options.openssl_cli
    botan = options.botan_cli

    if os.access(openssl, os.X_OK) is False:
        logging.error("Unable to access openssl binary at %s", openssl)

    if os.access(botan, os.X_OK) is False:
        logging.error("Unable to access botan binary at %s", botan)

    openssl_version = get_openssl_version(openssl)
    botan_version = get_botan_version(botan)

    logging.info("Comparing Botan %s with OpenSSL %s", botan_version, openssl_version)

    # for algo in sorted(HASH_EVP_MAP.keys()):
    #     result = bench_algo(openssl, botan, algo)
    #     print(result.result_string())

    print(bench_signature_algo(openssl, botan, "RSA").result_string())


    return 0

if __name__ == '__main__':
    sys.exit(main())
