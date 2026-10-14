#!/usr/bin/env python3
"""Extend the existing real-DHCP schedule with post-publication TCP children."""
import argparse
import json
from pathlib import Path
import socket
import time

import m5_dns_cache as driver

original_schedule = driver.schedule


def schedule(spec, port, upstream, folder, root):
    observations = original_schedule(spec, port, upstream, folder, root)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.bind((driver.CLIENT, 0))
        client.connect((driver.LISTEN, port))
        for host in ('leaseold.cache.test', 'leasenew.cache.test'):
            label = 'new-child-' + host
            query = driver.query(host, 0x3490)
            started = time.monotonic_ns()
            response = driver.exchange(port, query, True, client)
            completed = time.monotonic_ns()
            assert response is not None
            (folder / (label + '.query')).write_bytes(query)
            (folder / (label + '.reply')).write_bytes(response)
            observations.append({'label': label, 'query': driver.normalized(query),
                                 'reply': driver.normalized(response),
                                 'sent_monotonic_ns': started,
                                 'completed_monotonic_ns': completed})
    return observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--side', choices=('c', 'rust'), required=True)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.only = '^tcp-parent-lease-'
    driver.schedule = schedule
    status = driver.run(args)
    (args.out / 'extension.json').write_text(json.dumps({
        'driver_sha256': driver.sha256(__file__),
        'schedule': 'existing add/rename/release and retained child; then new TCP child queries old/new lease names',
    }, indent=2) + '\n')
    raise SystemExit(status)


if __name__ == '__main__':
    main()
